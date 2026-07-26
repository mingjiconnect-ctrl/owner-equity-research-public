from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .calculation_integrity import build_calculation_result
from .capital_allocation_policies import OFFICIAL_AUTHORITY_LEVELS
from .contracts import CalculationResult, CapitalAllocationEvent, Fact, SourceDocument
from .fingerprints import canonical_sha256
from .units import normalize_value, unit_spec

BRIDGE_POLICY_VERSION = "1.0.0"
BRIDGE_CALCULATOR_ID = "owner-research-capital-allocation-bridges"
FORBIDDEN_INPUT_CONCEPTS = frozenset(
    {
        "earnings_per_share",
        "eps_accretion",
        "return_on_equity",
        "roe",
        "stock_price",
        "share_price",
        "market_price",
        "target_price",
        "npv",
        "roic",
        "economic_profit",
        "dcf",
    }
)


@dataclass(frozen=True, slots=True)
class CapitalAllocationBridgePolicy:
    policy_id: str
    version: str
    event_type: str
    operation: str
    input_roles: tuple[str, ...]
    input_unit_rules: tuple[str, ...]
    output_concept: str
    output_unit: str


def _policy(
    policy_id: str,
    event_type: str,
    operation: str,
    input_roles: tuple[str, ...],
    input_unit_rules: tuple[str, ...],
    output_concept: str,
    output_unit: str,
) -> CapitalAllocationBridgePolicy:
    return CapitalAllocationBridgePolicy(
        policy_id=policy_id,
        version=BRIDGE_POLICY_VERSION,
        event_type=event_type,
        operation=operation,
        input_roles=input_roles,
        input_unit_rules=input_unit_rules,
        output_concept=output_concept,
        output_unit=output_unit,
    )


CAPITAL_ALLOCATION_BRIDGE_POLICIES = {
    item.policy_id: item
    for item in (
        _policy(
            "acquisition_consideration_residual",
            "acquisition",
            "total_less_components",
            (
                "purchase_price",
                "cash_consideration",
                "stock_consideration",
                "debt_assumed",
                "contingent_consideration",
            ),
            ("monetary",) * 5,
            "capital_allocation.acquisition_consideration_residual",
            "currency_units",
        ),
        _policy(
            "divestiture_consideration_residual",
            "divestiture",
            "total_less_components",
            (
                "announced_consideration",
                "cash_proceeds",
                "noncash_proceeds",
                "debt_transferred",
            ),
            ("monetary",) * 4,
            "capital_allocation.divestiture_consideration_residual",
            "currency_units",
        ),
        _policy(
            "equity_net_proceeds",
            "equity_issuance",
            "difference",
            ("gross_proceeds", "issuance_cost"),
            ("monetary", "monetary"),
            "capital_allocation.net_proceeds",
            "currency_units",
        ),
        _policy(
            "debt_issuance_incremental",
            "debt_issuance",
            "difference",
            ("principal_issued", "debt_refinanced"),
            ("monetary", "monetary"),
            "capital_allocation.incremental_debt",
            "currency_units",
        ),
        _policy(
            "debt_repayment_cash_funded",
            "debt_repayment",
            "difference",
            ("principal_repaid", "debt_refinanced"),
            ("monetary", "monetary"),
            "capital_allocation.cash_funded_repayment",
            "currency_units",
        ),
        _policy(
            "buyback_net_share_effect",
            "buyback",
            "total_less_components",
            (
                "shares_repurched",
                "sbc_shares_issued",
                "other_equity_shares_issued",
            ),
            ("shares", "shares", "shares"),
            "capital_allocation.net_shares_retired",
            "shares",
        ),
        _policy(
            "buyback_cash_per_share",
            "buyback",
            "monetary_per_share",
            ("cash_spent", "shares_repurched"),
            ("monetary", "shares"),
            "capital_allocation.cash_per_share_repurched",
            "currency_per_share",
        ),
        _policy(
            "dividend_declared_aggregate",
            "dividend",
            "per_share_times_shares",
            ("dividend_per_share_declared", "eligible_shares"),
            ("currency_per_share", "shares"),
            "capital_allocation.aggregate_dividend_declared",
            "currency_units",
        ),
        _policy(
            "gross_liquidity",
            "cash_accumulation",
            "sum",
            ("cash_and_equivalents", "restricted_cash", "marketable_securities"),
            ("monetary", "monetary", "monetary"),
            "capital_allocation.gross_liquidity",
            "currency_units",
        ),
    )
}


class CapitalAllocationBridgeError(ValueError):
    pass


def bridge_policy(
    policy_id: str,
    version: str = BRIDGE_POLICY_VERSION,
) -> CapitalAllocationBridgePolicy:
    try:
        policy = CAPITAL_ALLOCATION_BRIDGE_POLICIES[policy_id]
    except KeyError as exc:
        raise CapitalAllocationBridgeError("unregistered capital-allocation bridge policy") from exc
    if version != policy.version:
        raise CapitalAllocationBridgeError("unsupported capital-allocation bridge policy version")
    if len(policy.input_roles) != len(policy.input_unit_rules):
        raise CapitalAllocationBridgeError("bridge policy role and unit rules differ")
    return policy


def _number(fact: Fact) -> float:
    if (
        fact.value_type != "number"
        or isinstance(fact.value, bool)
        or not isinstance(fact.value, (int, float))
    ):
        raise CapitalAllocationBridgeError("bridge inputs must be numeric Facts")
    return float(fact.value)


def _validate_unit_rule(fact: Fact, rule: str) -> None:
    spec = unit_spec(fact.unit or "")
    if rule == "monetary" and spec.family != "monetary":
        raise CapitalAllocationBridgeError("bridge input requires a monetary unit")
    if rule == "shares" and fact.unit != "shares":
        raise CapitalAllocationBridgeError("bridge input requires shares")
    if rule == "currency_per_share" and fact.unit != "currency_per_share":
        raise CapitalAllocationBridgeError("bridge input requires currency per share")


def _event_fact_roles(event: CapitalAllocationEvent) -> dict[str, str]:
    roles: dict[str, str] = {}
    for binding in event.fact_bindings:
        role = binding["role_id"]
        if role in roles:
            raise CapitalAllocationBridgeError("Event repeats an economic Fact role")
        roles[role] = binding["fact_id"]
    return roles


def _validate_inputs(
    *,
    policy: CapitalAllocationBridgePolicy,
    event: CapitalAllocationEvent,
    facts_by_role: Mapping[str, Fact],
    source_documents: Sequence[SourceDocument],
    as_of_date: str,
) -> tuple[Fact, ...]:
    if event.event_type != policy.event_type:
        raise CapitalAllocationBridgeError("bridge policy does not match Event type")
    if event.lifecycle_status in {"cancelled", "superseded", "blocked"}:
        raise CapitalAllocationBridgeError("Event lifecycle is ineligible for a bridge")
    if set(facts_by_role) != set(policy.input_roles):
        raise CapitalAllocationBridgeError("bridge input roles do not match policy")
    event_roles = _event_fact_roles(event)
    documents = {item.document_id: item for item in source_documents}
    cutoff = date.fromisoformat(as_of_date)
    selected: list[Fact] = []
    for role, rule in zip(policy.input_roles, policy.input_unit_rules, strict=True):
        fact = facts_by_role[role]
        if event_roles.get(role) != fact.fact_id:
            raise CapitalAllocationBridgeError("bridge Fact is not reviewed by the Event")
        if fact.issuer_id != event.issuer_id:
            raise CapitalAllocationBridgeError("bridge Fact issuer mismatch")
        if any(token in fact.concept.casefold() for token in FORBIDDEN_INPUT_CONCEPTS):
            raise CapitalAllocationBridgeError("bridge input uses a forbidden result shortcut")
        try:
            document = documents[fact.source_document_id]
        except KeyError as exc:
            raise CapitalAllocationBridgeError("bridge Fact source is unavailable") from exc
        if (
            document.issuer_id != event.issuer_id
            or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
        ):
            raise CapitalAllocationBridgeError("bridge Fact requires an official issuer source")
        if date.fromisoformat(document.published_date) > cutoff:
            raise CapitalAllocationBridgeError("bridge Fact source follows the cutoff")
        if fact.period["end"] is not None and date.fromisoformat(fact.period["end"]) > cutoff:
            raise CapitalAllocationBridgeError("bridge Fact period follows the cutoff")
        _number(fact)
        _validate_unit_rule(fact, rule)
        selected.append(fact)
    if len({canonical_sha256(dict(item.period)) for item in selected}) != 1:
        raise CapitalAllocationBridgeError("bridge inputs require one comparable period")
    monetary = [item for item in selected if unit_spec(item.unit or "").currency_required]
    if len({item.currency for item in monetary}) > 1:
        raise CapitalAllocationBridgeError("bridge inputs require one currency")
    return tuple(selected)


def _calculate(
    policy: CapitalAllocationBridgePolicy,
    facts_by_role: Mapping[str, Fact],
) -> tuple[float, str | None]:
    values = {
        role: normalize_value(_number(fact), fact.unit or "")
        for role, fact in facts_by_role.items()
    }
    if policy.operation == "difference":
        value = values[policy.input_roles[0]] - values[policy.input_roles[1]]
    elif policy.operation == "sum":
        value = sum(values.values())
    elif policy.operation == "total_less_components":
        value = values[policy.input_roles[0]] - sum(
            values[role] for role in policy.input_roles[1:]
        )
    elif policy.operation == "monetary_per_share":
        denominator = values[policy.input_roles[1]]
        if denominator == 0:
            raise CapitalAllocationBridgeError("bridge share denominator cannot be zero")
        value = values[policy.input_roles[0]] / denominator
    elif policy.operation == "per_share_times_shares":
        value = values[policy.input_roles[0]] * values[policy.input_roles[1]]
    else:
        raise CapitalAllocationBridgeError("unsupported bridge operation")
    currency = next(
        (fact.currency for fact in facts_by_role.values() if fact.currency is not None),
        None,
    )
    return float(value), currency


def run_capital_allocation_bridge(
    policy_id: str,
    *,
    event: CapitalAllocationEvent,
    facts_by_role: Mapping[str, Fact],
    source_documents: Sequence[SourceDocument],
    as_of_date: str,
    generated_at: str,
) -> CalculationResult:
    policy = bridge_policy(policy_id)
    selected = _validate_inputs(
        policy=policy,
        event=event,
        facts_by_role=facts_by_role,
        source_documents=source_documents,
        as_of_date=as_of_date,
    )
    value, currency = _calculate(policy, facts_by_role)
    facts = {item.fact_id: item for item in selected}
    code_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    calculation_id = (
        f"calc:{event.issuer_id}:{policy.policy_id}:"
        f"{canonical_sha256({'event': event.fingerprint, 'facts': sorted(facts)})[:20]}"
    )
    payload = {
        "schema_version": "2.0.0",
        "calculation_id": calculation_id,
        "issuer_id": event.issuer_id,
        "concept": policy.output_concept,
        "value_type": "number",
        "value": value,
        "unit": policy.output_unit,
        "currency": currency,
        "period": dict(selected[0].period),
        "generator": "deterministic_program",
        "calculator_id": BRIDGE_CALCULATOR_ID,
        "calculator_version": policy.version,
        "code_sha256": code_sha,
        "input_fact_ids": sorted(facts),
        "input_assumption_ids": [],
        "input_calculation_ids": [],
        "input_period_ids": [],
        "input_bindings": {role: facts_by_role[role].fact_id for role in policy.input_roles},
        "input_fingerprint": "0" * 64,
        "output_fingerprint": "0" * 64,
        "generated_at": generated_at,
    }
    return build_calculation_result(
        payload,
        facts=facts,
        assumptions={},
        calculations={},
        periods={},
    )
