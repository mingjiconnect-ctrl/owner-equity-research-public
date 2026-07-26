from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .business_quality_policies import mechanism_policy
from .calculation_integrity import build_calculation_result
from .contracts import CalculationResult, Fact, FiscalPeriod, SegmentSnapshot
from .fingerprints import canonical_sha256
from .units import unit_spec

DIAGNOSTIC_VERSION = "1.0.0"
CALCULATOR_ID = "owner-research-mechanism-diagnostics"
FORBIDDEN_CONCEPTS = frozenset(
    {"nopat", "invested_capital", "roic", "incremental_roic", "economic_profit", "dcf"}
)


@dataclass(frozen=True, slots=True)
class DiagnosticPolicy:
    policy_id: str
    version: str
    calculator_id: str
    mechanism: str
    role_id: str
    polarity: str
    operation: str
    input_roles: tuple[str, ...]
    input_unit_rules: tuple[str, ...]
    period_semantics: str
    allowed_scope_types: frozenset[str]
    minimum_observations: int
    output_concept: str
    forbidden_shortcuts: frozenset[str]


def _policy(
    policy_id: str,
    mechanism: str,
    role_id: str,
    operation: str,
    input_roles: tuple[str, ...],
    *,
    input_unit_rules: tuple[str, ...] | None = None,
    polarity: str = "support",
    period_semantics: str = "same_period",
) -> DiagnosticPolicy:
    mechanism_policy_record = mechanism_policy(mechanism)
    return DiagnosticPolicy(
        policy_id,
        DIAGNOSTIC_VERSION,
        CALCULATOR_ID,
        mechanism,
        role_id,
        polarity,
        operation,
        input_roles,
        input_unit_rules or tuple("same_unit" for _ in input_roles),
        period_semantics,
        frozenset({"issuer_wide", "segment_specific"}),
        2 if operation in {"difference", "growth"} else 1,
        f"business_quality.{policy_id}",
        mechanism_policy_record.forbidden_single_indicators | FORBIDDEN_CONCEPTS,
    )


DIAGNOSTIC_POLICIES = {
    item.policy_id: item
    for item in (
        _policy(
            "price_mix_growth",
            "brand_pricing_power",
            "price_mix",
            "growth",
            ("current", "prior"),
            input_unit_rules=("same_unit", "same_unit"),
            period_semantics="successive_periods",
        ),
        _policy(
            "volume_resilience_growth",
            "brand_pricing_power",
            "volume_share_resilience",
            "growth",
            ("current", "prior"),
            input_unit_rules=("same_unit", "same_unit"),
            period_semantics="successive_periods",
        ),
        _policy(
            "promotion_growth",
            "brand_pricing_power",
            "promotion_competitor_response",
            "growth",
            ("current", "prior"),
            input_unit_rules=("same_unit", "same_unit"),
            polarity="counterevidence",
            period_semantics="successive_periods",
        ),
        _policy(
            "retention_change",
            "switching_cost",
            "retention_churn",
            "difference",
            ("current", "prior"),
            input_unit_rules=("same_unit", "same_unit"),
            period_semantics="successive_periods",
        ),
        _policy(
            "churn_complement",
            "switching_cost",
            "retention_churn",
            "complement",
            ("rate",),
            input_unit_rules=("ratio",),
        ),
        _policy(
            "network_density",
            "network_effect",
            "network_density",
            "ratio",
            ("numerator", "denominator"),
            input_unit_rules=("same_unit", "same_unit"),
        ),
        _policy(
            "subsidy_intensity",
            "network_effect",
            "subsidy_multihoming",
            "ratio",
            ("numerator", "denominator"),
            input_unit_rules=("same_unit", "same_unit"),
            polarity="counterevidence",
        ),
        _policy(
            "unit_cost_growth",
            "scale_cost_advantage",
            "unit_cost",
            "growth",
            ("current", "prior"),
            input_unit_rules=("same_unit", "same_unit"),
            period_semantics="successive_periods",
        ),
        _policy(
            "capital_intensity",
            "scale_cost_advantage",
            "diseconomy_capital_intensity",
            "ratio",
            ("numerator", "denominator"),
            input_unit_rules=("same_unit", "same_unit"),
            polarity="counterevidence",
        ),
        _policy(
            "sales_efficiency",
            "distribution",
            "acquisition_fulfillment_economics",
            "ratio",
            ("numerator", "denominator"),
            input_unit_rules=("same_unit", "same_unit"),
        ),
        _policy(
            "capacity_utilization",
            "efficient_scale",
            "minimum_efficient_scale",
            "ratio",
            ("numerator", "denominator"),
            input_unit_rules=("same_unit", "same_unit"),
        ),
        _policy(
            "cycle_time_change",
            "process_execution",
            "cycle_quality_service",
            "difference",
            ("current", "prior"),
            input_unit_rules=("same_unit", "same_unit"),
            period_semantics="successive_periods",
        ),
        _policy(
            "revenue_per_location",
            "distribution",
            "coverage",
            "per_unit",
            ("numerator", "denominator"),
            input_unit_rules=("monetary", "locations"),
        ),
        _policy(
            "ip_direct_evidence", "intellectual_property", "protected_right", "direct_only", ()
        ),
        _policy("license_direct_evidence", "regulatory_license", "license", "direct_only", ()),
        _policy("data_direct_evidence", "data_learning", "data_uniqueness", "direct_only", ()),
    )
}


class MechanismDiagnosticError(ValueError):
    pass


def diagnostic_policy(policy_id: str, version: str = DIAGNOSTIC_VERSION) -> DiagnosticPolicy:
    try:
        policy = DIAGNOSTIC_POLICIES[policy_id]
    except KeyError as exc:
        raise MechanismDiagnosticError("unregistered diagnostic policy") from exc
    if version != policy.version:
        raise MechanismDiagnosticError("unsupported diagnostic policy version")
    mechanism = mechanism_policy(policy.mechanism)
    expected = (
        mechanism.support_roles if policy.polarity == "support" else mechanism.counterevidence_roles
    )
    if policy.role_id not in expected:
        raise MechanismDiagnosticError("diagnostic role is not registered by the mechanism")
    if len(policy.input_unit_rules) != len(policy.input_roles):
        raise MechanismDiagnosticError("diagnostic unit rules do not match input roles")
    return policy


def _number(fact: Fact) -> float:
    if (
        fact.value_type != "number"
        or isinstance(fact.value, bool)
        or not isinstance(fact.value, (int, float))
    ):
        raise MechanismDiagnosticError("diagnostic inputs must be numeric Facts")
    return float(fact.value)


def _period_bounds(period: FiscalPeriod) -> set[tuple[str, str]]:
    return {
        (period.quarter_start, period.quarter_end),
        (period.cumulative_start, period.cumulative_end),
        (period.ttm_start, period.cumulative_end),
    }


def _validate_input_semantics(
    policy: DiagnosticPolicy,
    facts_by_role: Mapping[str, Fact],
    periods_by_role: Mapping[str, FiscalPeriod],
) -> None:
    if set(periods_by_role) != set(policy.input_roles):
        raise MechanismDiagnosticError("diagnostic period roles do not match policy")
    for role, rule in zip(policy.input_roles, policy.input_unit_rules, strict=True):
        fact = facts_by_role[role]
        period = periods_by_role[role]
        if fact.issuer_id != period.issuer_id:
            raise MechanismDiagnosticError("Fact and FiscalPeriod issuer mismatch")
        fact_period = (fact.period["start"], fact.period["end"])
        if fact_period not in _period_bounds(period):
            raise MechanismDiagnosticError("Fact period is not represented by its FiscalPeriod")
        spec = unit_spec(fact.unit or "")
        if rule == "ratio" and fact.unit != "ratio":
            raise MechanismDiagnosticError("diagnostic input requires a ratio")
        if rule == "monetary" and spec.family != "monetary":
            raise MechanismDiagnosticError("diagnostic input requires a monetary unit")
        if rule not in {"same_unit", "ratio", "monetary"} and fact.unit != rule:
            raise MechanismDiagnosticError(f"diagnostic input requires unit {rule}")
    if policy.period_semantics == "successive_periods":
        current_period = periods_by_role["current"]
        prior_period = periods_by_role["prior"]
        if date.fromisoformat(current_period.cumulative_end) <= date.fromisoformat(
            prior_period.cumulative_end
        ):
            raise MechanismDiagnosticError("diagnostic periods are not successive")
    elif len({period.period_id for period in periods_by_role.values()}) != 1:
        raise MechanismDiagnosticError("same-period diagnostic uses different FiscalPeriods")


def _require_same_unit(left: Fact, right: Fact) -> None:
    if left.unit != right.unit or left.currency != right.currency:
        raise MechanismDiagnosticError("diagnostic inputs require the same unit and currency")


def run_diagnostic(
    policy_id: str,
    *,
    facts_by_role: Mapping[str, Fact],
    periods_by_role: Mapping[str, FiscalPeriod],
    scope: Mapping[str, object],
    segment_snapshots: tuple[SegmentSnapshot, ...],
    generated_at: str,
) -> CalculationResult:
    policy = diagnostic_policy(policy_id)
    if policy.operation == "direct_only":
        raise MechanismDiagnosticError(
            "diagnostic policy requires direct evidence, not calculation"
        )
    if set(facts_by_role) != set(policy.input_roles):
        raise MechanismDiagnosticError("diagnostic input roles do not match policy")
    facts = tuple(facts_by_role[role] for role in policy.input_roles)
    if len(facts) < policy.minimum_observations or len({fact.issuer_id for fact in facts}) != 1:
        raise MechanismDiagnosticError("diagnostic observations or issuer are invalid")
    forbidden_matches = {
        token
        for fact in facts
        for token in policy.forbidden_shortcuts
        if token in fact.concept.lower()
    }
    if forbidden_matches:
        if forbidden_matches & FORBIDDEN_CONCEPTS:
            raise MechanismDiagnosticError(
                "valuation concepts are forbidden in mechanism diagnostics"
            )
        raise MechanismDiagnosticError("single-indicator shortcuts are forbidden")
    scope_type = scope.get("scope_type")
    if scope_type not in policy.allowed_scope_types:
        raise MechanismDiagnosticError("diagnostic scope lacks a deterministic Fact mapping")
    if scope["scope_type"] == "segment_specific":
        if not segment_snapshots:
            raise MechanismDiagnosticError("segment scope requires SegmentSnapshots")
        segment_ids = set(scope.get("segment_definition_ids", ()))
        wrong_issuer = any(
            snapshot.issuer_id != facts[0].issuer_id for snapshot in segment_snapshots
        )
        if wrong_issuer or not segment_ids:
            raise MechanismDiagnosticError("segment scope and diagnostic issuer are invalid")
        snapshots_by_period = {
            snapshot.fiscal_period_id: snapshot for snapshot in segment_snapshots
        }
        for role, fact in facts_by_role.items():
            period_id = periods_by_role[role].period_id
            snapshot = snapshots_by_period.get(period_id)
            if snapshot is None or fact.fact_id not in {
                item["fact_id"]
                for item in snapshot.metric_assignments
                if item["segment_id"] in segment_ids
            }:
                raise MechanismDiagnosticError(
                    "diagnostic Fact is not assigned to its period segment scope"
                )
    _validate_input_semantics(policy, facts_by_role, periods_by_role)
    values = [_number(fact) for fact in facts]
    if policy.operation in {"difference", "growth"}:
        current, prior = facts
        if current.concept != prior.concept:
            raise MechanismDiagnosticError("successive-period Facts are not comparable")
        _require_same_unit(current, prior)
        if policy.operation == "difference":
            value, unit, currency = values[0] - values[1], current.unit, current.currency
        else:
            if values[1] == 0:
                raise MechanismDiagnosticError("growth prior value cannot be zero")
            value, unit, currency = values[0] / values[1] - 1, "ratio", None
        output_period = current.period
    elif policy.operation == "complement":
        fact = facts[0]
        if fact.unit != "ratio" or not 0 <= values[0] <= 1:
            raise MechanismDiagnosticError("complement requires a bounded ratio")
        value, unit, currency, output_period = 1 - values[0], "ratio", None, fact.period
    else:
        numerator, denominator = facts
        if dict(numerator.period) != dict(denominator.period) or values[1] == 0:
            raise MechanismDiagnosticError(
                "ratio inputs require one period and nonzero denominator"
            )
        if policy.operation == "ratio":
            _require_same_unit(numerator, denominator)
            unit, currency = "ratio", None
        elif policy.operation == "per_unit":
            if unit_spec(numerator.unit).family != "monetary" or not unit_spec(
                denominator.unit
            ).family.startswith("count:"):
                raise MechanismDiagnosticError("per-unit inputs require monetary over count")
            unit = "currency_per_location"
            currency = numerator.currency
        else:
            raise MechanismDiagnosticError("unsupported deterministic operation")
        value, output_period = values[0] / values[1], numerator.period
    fact_map = {fact.fact_id: fact for fact in facts}
    period_map = {period.period_id: period for period in periods_by_role.values()}
    code_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    calculation_id = (
        f"calc:{facts[0].issuer_id}:{policy.policy_id}:"
        f"{canonical_id(fact_map, period_map)}"
    )
    payload = {
        "schema_version": "2.0.0",
        "calculation_id": calculation_id,
        "issuer_id": facts[0].issuer_id,
        "concept": policy.output_concept,
        "value_type": "number",
        "value": value,
        "unit": unit,
        "currency": currency,
        "period": dict(output_period),
        "generator": "deterministic_program",
        "calculator_id": CALCULATOR_ID,
        "calculator_version": policy.version,
        "code_sha256": code_sha,
        "input_fact_ids": sorted(fact_map),
        "input_assumption_ids": [],
        "input_calculation_ids": [],
        "input_period_ids": sorted(period_map),
        "input_bindings": {
            **{role: fact.fact_id for role, fact in facts_by_role.items()},
            **{
                f"{role}_period": periods_by_role[role].period_id
                for role in policy.input_roles
            },
        },
        "input_fingerprint": "0" * 64,
        "output_fingerprint": "0" * 64,
        "generated_at": generated_at,
    }
    return build_calculation_result(
        payload,
        facts=fact_map,
        assumptions={},
        calculations={},
        periods=period_map,
    )


def canonical_id(facts: dict[str, Fact], periods: dict[str, FiscalPeriod]) -> str:
    return canonical_sha256(
        {
            "facts": {key: value.fingerprint for key, value in sorted(facts.items())},
            "periods": {key: value.fingerprint for key, value in sorted(periods.items())},
        }
    )[:20]
