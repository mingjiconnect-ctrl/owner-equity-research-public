"""Closed Phase 5D-0 policies for governed, price-blind valuation assumptions."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .fingerprints import canonical_sha256

ASSUMPTION_CANDIDATE_POLICY_ID = "valuation-assumption-candidate"
ASSUMPTION_CANDIDATE_POLICY_VERSION = "2.0.0"
MARKET_REFERENCE_POLICY_ID = "market-reference"
MARKET_REFERENCE_POLICY_VERSION = "4.0.0"
HANDOFF_POLICY_ID = "valuation-handoff"
HANDOFF_POLICY_VERSION = "2.0.0"

ASSUMPTION_SLOT_POLICY_ID = "assumption-slot"
ASSUMPTION_SLOT_POLICY_VERSION = "1.0.0"
ASSUMPTION_EVIDENCE_POLICY_ID = "assumption-evidence"
ASSUMPTION_EVIDENCE_POLICY_VERSION = "1.0.0"
SUPPLEMENTAL_REFERENCE_POLICY_ID = "price-blind-reference"
SUPPLEMENTAL_REFERENCE_POLICY_VERSION = "1.0.0"
PRICE_BLIND_FREEZE_POLICY_ID = "price-blind-freeze"
PRICE_BLIND_FREEZE_POLICY_VERSION = "1.0.0"

MCKINSEY_SCENARIOS = frozenset({"black_swan", "bear", "base", "bull"})
MCKINSEY_CONCEPTS = frozenset(
    {
        "revenue",
        "nopat",
        "ending_invested_capital",
        "wacc",
        "terminal_growth",
        "terminal_ronic",
        "terminal_margin",
        "terminal_roic",
        "steady_state_tolerance",
    }
)
PENMAN_CONCEPTS = frozenset(
    {
        "sales",
        "operating_income_after_tax",
        "ending_noa",
        "hurdle_rate",
        "growth_rate",
    }
)

HANDOFF_STATES = (
    "evidence_open",
    "price_blind_candidates_reviewed",
    "price_blind_input_frozen",
    "market_reference_allowed",
    "request_compiled",
    "kernel_result_frozen",
)
HANDOFF_TRANSITIONS = {
    current: following
    for current, following in zip(HANDOFF_STATES, HANDOFF_STATES[1:], strict=False)
}

PINNED_KERNEL_REPOSITORY = "mingjiconnect-ctrl/owner-valuation-kernel"
PINNED_KERNEL_TAG = "v2.0.0-rc.2"
PINNED_KERNEL_COMMIT = "be9b0773d5a78f5f8a33ba982494512668df85fe"
PINNED_KERNEL_PLUGIN_VERSION = "2.0.0-rc.2"
PINNED_KERNEL_SCHEMA_COUNT = 8


def legacy_handoff_v2_kernel_identity() -> dict[str, object]:
    """Return the frozen public Handoff-v2 shape, never an execution authority.

    Phase 5E-2A.2 may change only the Snapshot public Schema. Component-lock 1.2.0 and the
    price-blind artifact carry the authoritative rc.2 identity; this legacy field remains solely
    so the unchanged Handoff-v2 public contract can be replayed until its own authorized upgrade.
    """

    return {
        "repository": "mingjiconnect-ctrl/owner-valuation-kernel",
        "tag": "v2.0.0-rc.1",
        "commit": "a7dd1528c34f09702686b32ffbb8a397439665f0",
        "plugin_version": "2.0.0-rc.1",
        "public_schema_sha256": {
            "schemas/assumption-ledger.schema.json": (
                "2232642332dc6444c784e21746cbd16bf8d4cd74fc483a0a345d95f98fc97a7a"
            ),
            "schemas/fact-ledger.schema.json": (
                "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
            ),
            "schemas/sec-company-profile.schema.json": (
                "539b76ad7974162ba36b513c029d7d8377d352de4e150425c19c4dea620fbf06"
            ),
            "schemas/sec-company-review.schema.json": (
                "24dfa87fa94c0362569979e454cd1f536eef7c7845473567e4e88df872335205"
            ),
            "schemas/sec-evidence-pack.schema.json": (
                "3cf634214584d54d83b0d397da3139ca30815a44e99e7ecc24c3258b25a7b91a"
            ),
            "schemas/sec-scenario-policy.schema.json": (
                "74c0b0cce146891825fcf4599658f99a20fa66924cf07655895dcece00010065"
            ),
            "schemas/valuation-request.schema.json": (
                "3f6c37604bf726229a307ce3196bdf78efae98c6111c640c2cdda78bdb8f471f"
            ),
            "schemas/valuation-result.schema.json": (
                "353ea8923234f8df7eaef81186f1552be8a3497840c2cb0a04f25baa95c297de"
            ),
        },
    }


@dataclass(frozen=True, slots=True)
class MethodAssumptionPolicy:
    method_scope: str
    concepts: frozenset[str]
    scenarios: frozenset[str]
    scenario_required: bool


METHOD_ASSUMPTION_POLICIES = {
    "mckinsey": MethodAssumptionPolicy(
        method_scope="mckinsey",
        concepts=MCKINSEY_CONCEPTS,
        scenarios=MCKINSEY_SCENARIOS,
        scenario_required=True,
    ),
    "penman": MethodAssumptionPolicy(
        method_scope="penman",
        concepts=PENMAN_CONCEPTS,
        scenarios=frozenset(),
        scenario_required=False,
    ),
}


@dataclass(frozen=True, slots=True)
class AssumptionSlotPolicy:
    slot_kind: str
    method_scope: str
    kernel_concept: str
    horizon_kind: str
    unit_family: str
    scenario_required: bool
    allowed_evidence_roles: frozenset[str]
    required_support_roles: frozenset[str]


COMMON_OPERATING_ROLES = frozenset(
    {
        "mapped_historical_fact",
        "reviewed_management_guidance",
        "reviewed_business_quality",
        "reviewed_accounting_quality",
        "reviewed_capital_allocation",
        "counterevidence",
        "falsification",
        "limitation",
    }
)
RATE_ROLES = frozenset(
    {
        "mapped_historical_fact",
        "macro_risk_free",
        "macro_inflation",
        "macro_long_run_growth",
        "equity_risk_premium",
        "industry_beta",
        "debt_cost",
        "capital_structure",
        "tax_rate",
        "owner_hurdle_policy",
        "opportunity_cost",
        "reviewed_business_quality",
        "reviewed_accounting_quality",
        "counterevidence",
        "falsification",
        "limitation",
    }
)

_SLOT_PATTERNS: tuple[tuple[re.Pattern[str], AssumptionSlotPolicy], ...] = (
    (
        re.compile(
            r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\.forecast\."
            r"(?P<year>[0-9]{4})\.(?P<concept>revenue|nopat|ending_invested_capital)$"
        ),
        AssumptionSlotPolicy(
            slot_kind="annual_forecast",
            method_scope="mckinsey",
            kernel_concept="{concept}",
            horizon_kind="period",
            unit_family="monetary",
            scenario_required=True,
            allowed_evidence_roles=COMMON_OPERATING_ROLES,
            required_support_roles=frozenset({"mapped_historical_fact"}),
        ),
    ),
    (
        re.compile(r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\.wacc$"),
        AssumptionSlotPolicy(
            slot_kind="wacc",
            method_scope="mckinsey",
            kernel_concept="wacc",
            horizon_kind="point_in_time",
            unit_family="rate",
            scenario_required=True,
            allowed_evidence_roles=RATE_ROLES,
            required_support_roles=frozenset(
                {
                    "macro_risk_free",
                    "equity_risk_premium",
                    "industry_beta",
                    "debt_cost",
                    "capital_structure",
                    "tax_rate",
                }
            ),
        ),
    ),
    (
        re.compile(
            r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\."
            r"(?P<concept>terminal_growth)$"
        ),
        AssumptionSlotPolicy(
            slot_kind="terminal_growth",
            method_scope="mckinsey",
            kernel_concept="{concept}",
            horizon_kind="terminal",
            unit_family="rate",
            scenario_required=True,
            allowed_evidence_roles=RATE_ROLES | COMMON_OPERATING_ROLES,
            required_support_roles=frozenset(
                {"mapped_historical_fact", "macro_long_run_growth"}
            ),
        ),
    ),
    (
        re.compile(
            r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\."
            r"(?P<concept>terminal_ronic|terminal_roic)$"
        ),
        AssumptionSlotPolicy(
            slot_kind="terminal_return",
            method_scope="mckinsey",
            kernel_concept="{concept}",
            horizon_kind="terminal",
            unit_family="rate",
            scenario_required=True,
            allowed_evidence_roles=RATE_ROLES | COMMON_OPERATING_ROLES,
            required_support_roles=frozenset(
                {"mapped_historical_fact", "reviewed_business_quality"}
            ),
        ),
    ),
    (
        re.compile(
            r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\.terminal_margin$"
        ),
        AssumptionSlotPolicy(
            slot_kind="terminal_margin",
            method_scope="mckinsey",
            kernel_concept="terminal_margin",
            horizon_kind="terminal",
            unit_family="rate",
            scenario_required=True,
            allowed_evidence_roles=RATE_ROLES | COMMON_OPERATING_ROLES,
            required_support_roles=frozenset(
                {"mapped_historical_fact", "reviewed_accounting_quality"}
            ),
        ),
    ),
    (
        re.compile(
            r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\."
            r"steady_state_tolerance$"
        ),
        AssumptionSlotPolicy(
            slot_kind="steady_state_tolerance",
            method_scope="mckinsey",
            kernel_concept="steady_state_tolerance",
            horizon_kind="terminal",
            unit_family="rate",
            scenario_required=True,
            allowed_evidence_roles=RATE_ROLES | COMMON_OPERATING_ROLES,
            required_support_roles=frozenset({"mapped_historical_fact"}),
        ),
    ),
    (
        re.compile(
            r"^penman\.forecast\.(?P<year>[0-9]{4})\."
            r"(?P<concept>sales|operating_income_after_tax|ending_noa)$"
        ),
        AssumptionSlotPolicy(
            slot_kind="annual_forecast",
            method_scope="penman",
            kernel_concept="{concept}",
            horizon_kind="period",
            unit_family="monetary",
            scenario_required=False,
            allowed_evidence_roles=COMMON_OPERATING_ROLES,
            required_support_roles=frozenset({"mapped_historical_fact"}),
        ),
    ),
    (
        re.compile(r"^penman\.primary_hurdle$"),
        AssumptionSlotPolicy(
            slot_kind="primary_hurdle",
            method_scope="penman",
            kernel_concept="hurdle_rate",
            horizon_kind="point_in_time",
            unit_family="rate",
            scenario_required=False,
            allowed_evidence_roles=RATE_ROLES,
            required_support_roles=frozenset({"owner_hurdle_policy", "opportunity_cost"}),
        ),
    ),
    (
        re.compile(r"^penman\.hurdle_grid\.(?P<index>[0-9]{2})$"),
        AssumptionSlotPolicy(
            slot_kind="hurdle_grid",
            method_scope="penman",
            kernel_concept="hurdle_rate",
            horizon_kind="point_in_time",
            unit_family="rate",
            scenario_required=False,
            allowed_evidence_roles=RATE_ROLES,
            required_support_roles=frozenset({"owner_hurdle_policy"}),
        ),
    ),
    (
        re.compile(r"^penman\.(growth_grid\.(?P<index>[0-9]{2})|long_run_growth)$"),
        AssumptionSlotPolicy(
            slot_kind="growth_grid",
            method_scope="penman",
            kernel_concept="growth_rate",
            horizon_kind="terminal",
            unit_family="rate",
            scenario_required=False,
            allowed_evidence_roles=RATE_ROLES | COMMON_OPERATING_ROLES,
            required_support_roles=frozenset({"macro_long_run_growth"}),
        ),
    ),
    (
        re.compile(
            r"^penman\.challenge\.(?P<year>[0-9]{4})\.(?P<concept>sales|ending_noa)$"
        ),
        AssumptionSlotPolicy(
            slot_kind="challenge_path",
            method_scope="penman",
            kernel_concept="{concept}",
            horizon_kind="period",
            unit_family="monetary",
            scenario_required=False,
            allowed_evidence_roles=COMMON_OPERATING_ROLES,
            required_support_roles=frozenset({"mapped_historical_fact"}),
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class SupplementalReferenceRolePolicy:
    role: str
    authority_levels: frozenset[str]
    requires_commit_pinned_url: bool = False


SUPPLEMENTAL_REFERENCE_ROLES = {
    "macro_risk_free": SupplementalReferenceRolePolicy(
        "macro_risk_free", frozenset({"primary_regulatory"})
    ),
    "macro_inflation": SupplementalReferenceRolePolicy(
        "macro_inflation", frozenset({"primary_regulatory"})
    ),
    "macro_long_run_growth": SupplementalReferenceRolePolicy(
        "macro_long_run_growth", frozenset({"primary_regulatory"})
    ),
    "equity_risk_premium": SupplementalReferenceRolePolicy(
        "equity_risk_premium", frozenset({"audited_secondary", "market_reference"})
    ),
    "industry_beta": SupplementalReferenceRolePolicy(
        "industry_beta", frozenset({"audited_secondary", "market_reference"})
    ),
    "opportunity_cost": SupplementalReferenceRolePolicy(
        "opportunity_cost",
        frozenset({"primary_regulatory", "audited_secondary", "market_reference"}),
    ),
    "owner_hurdle_policy": SupplementalReferenceRolePolicy(
        "owner_hurdle_policy", frozenset({"secondary"}), requires_commit_pinned_url=True
    ),
    "counterevidence": SupplementalReferenceRolePolicy(
        "counterevidence",
        frozenset(
            {"primary_regulatory", "audited_secondary", "secondary", "market_reference"}
        ),
    ),
    "falsification": SupplementalReferenceRolePolicy(
        "falsification",
        frozenset(
            {"primary_regulatory", "audited_secondary", "secondary", "market_reference"}
        ),
    ),
    "limitation": SupplementalReferenceRolePolicy(
        "limitation",
        frozenset(
            {"primary_regulatory", "audited_secondary", "secondary", "market_reference"}
        ),
    ),
}

RESEARCH_BUNDLE_ONLY_ROLES = frozenset(
    {
        "mapped_historical_fact",
        "reviewed_management_guidance",
        "reviewed_business_quality",
        "reviewed_accounting_quality",
        "reviewed_capital_allocation",
        "debt_cost",
        "capital_structure",
        "tax_rate",
        "counterevidence",
        "falsification",
        "limitation",
    }
)

TARGET_SECURITY_FORBIDDEN_CONCEPT_TOKENS = frozenset(
    {
        "market_quote",
        "share_price",
        "market_cap",
        "market_equity_value",
        "trading_multiple",
        "implied_return",
        "implied_beta",
    }
)


def method_assumption_policy(method_scope: str) -> MethodAssumptionPolicy:
    try:
        return METHOD_ASSUMPTION_POLICIES[method_scope]
    except KeyError as exc:
        raise KeyError(f"unknown valuation assumption method: {method_scope}") from exc


def assumption_slot_policy(slot_id: str) -> AssumptionSlotPolicy:
    for pattern, template in _SLOT_PATTERNS:
        match = pattern.fullmatch(slot_id)
        if match is None:
            continue
        concept = template.kernel_concept
        if concept == "{concept}":
            concept = match.group("concept")
        return AssumptionSlotPolicy(
            slot_kind=template.slot_kind,
            method_scope=template.method_scope,
            kernel_concept=concept,
            horizon_kind=template.horizon_kind,
            unit_family=template.unit_family,
            scenario_required=template.scenario_required,
            allowed_evidence_roles=template.allowed_evidence_roles,
            required_support_roles=template.required_support_roles,
        )
    raise KeyError(f"unknown valuation assumption slot: {slot_id}")


def _registry_payload() -> dict[str, object]:
    return {
        "method_policies": {
            key: {
                **asdict(value),
                "concepts": sorted(value.concepts),
                "scenarios": sorted(value.scenarios),
            }
            for key, value in sorted(METHOD_ASSUMPTION_POLICIES.items())
        },
        "slot_patterns": [
            {
                "pattern": pattern.pattern,
                **asdict(policy),
                "allowed_evidence_roles": sorted(policy.allowed_evidence_roles),
                "required_support_roles": sorted(policy.required_support_roles),
            }
            for pattern, policy in _SLOT_PATTERNS
        ],
    }


def assumption_slot_policy_sha256() -> str:
    return canonical_sha256(
        {
            "policy_id": ASSUMPTION_SLOT_POLICY_ID,
            "policy_version": ASSUMPTION_SLOT_POLICY_VERSION,
            "registry": _registry_payload(),
        }
    )


def assumption_evidence_policy_sha256() -> str:
    return canonical_sha256(
        {
            "policy_id": ASSUMPTION_EVIDENCE_POLICY_ID,
            "policy_version": ASSUMPTION_EVIDENCE_POLICY_VERSION,
            "research_bundle_only_roles": sorted(RESEARCH_BUNDLE_ONLY_ROLES),
            "supplemental_roles": {
                key: {
                    "authority_levels": sorted(value.authority_levels),
                    "requires_commit_pinned_url": value.requires_commit_pinned_url,
                }
                for key, value in sorted(SUPPLEMENTAL_REFERENCE_ROLES.items())
            },
            "target_security_forbidden_tokens": sorted(
                TARGET_SECURITY_FORBIDDEN_CONCEPT_TOKENS
            ),
        }
    )


def price_blind_freeze_policy_sha256() -> str:
    return canonical_sha256(
        {
            "policy_id": PRICE_BLIND_FREEZE_POLICY_ID,
            "policy_version": PRICE_BLIND_FREEZE_POLICY_VERSION,
            "handoff_states": HANDOFF_STATES,
            "protected_hashes": (
                "price_blind_input_fingerprint",
                "protected_mckinsey_sha256",
                "protected_penman_assumptions_sha256",
            ),
            "restart_on_drift": True,
            "quarantine_prior_market_references": True,
        }
    )


def empty_supplemental_reference_closure_sha256() -> str:
    return canonical_sha256(
        {
            "policy_id": SUPPLEMENTAL_REFERENCE_POLICY_ID,
            "policy_version": SUPPLEMENTAL_REFERENCE_POLICY_VERSION,
            "documents": [],
            "facts": [],
        }
    )
