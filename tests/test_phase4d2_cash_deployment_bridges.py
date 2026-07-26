from __future__ import annotations

from dataclasses import replace

import pytest

from owner_research.capital_allocation_bridges import (
    BRIDGE_CALCULATOR_ID,
    BRIDGE_POLICY_VERSION,
    CAPITAL_ALLOCATION_BRIDGE_POLICIES,
    CapitalAllocationBridgeError,
    bridge_policy,
    run_capital_allocation_bridge,
)
from owner_research.contracts import CapitalAllocationEvent, Fact, SourceDocument
from owner_research.validation import ContractGraph

PERIOD = {"start": "2026-01-01", "end": "2026-06-30"}


def _document(
    document_id: str = "doc:acme:2026-q2",
    *,
    issuer_id: str = "issuer:acme",
    published_date: str = "2026-07-01",
    authority_level: str = "primary_regulatory",
) -> SourceDocument:
    return SourceDocument(
        schema_version="1.0.0",
        document_id=document_id,
        issuer_id=issuer_id,
        document_type="10-Q",
        period=PERIOD,
        published_date=published_date,
        retrieved_at="2026-07-01T20:00:00Z",
        source_url=f"https://www.sec.gov/Archives/{document_id}.htm",
        authority_level=authority_level,
        content_sha256="a" * 64,
    )


def _fact(
    role: str,
    value: float,
    unit: str,
    *,
    currency: str | None,
    document: SourceDocument,
    concept: str | None = None,
    period: dict[str, str] = PERIOD,
) -> Fact:
    return Fact(
        schema_version="2.0.0",
        fact_id=f"fact:{document.issuer_id}:{role}",
        issuer_id=document.issuer_id,
        concept=concept or role,
        value_type="number",
        value=value,
        unit=unit,
        currency=currency,
        period=period,
        source_document_id=document.document_id,
        source_locator=f"table:{role}",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )


def _event(
    event_type: str,
    facts_by_role: dict[str, Fact],
    *,
    lifecycle_status: str = "completed",
) -> CapitalAllocationEvent:
    return CapitalAllocationEvent(
        schema_version="2.0.0",
        event_id=f"capital-event:issuer:acme:{event_type}",
        issuer_id="issuer:acme",
        event_policy_id=f"capital-allocation-event/{event_type}",
        event_policy_version="1.0.0",
        economic_event_key="e" * 64,
        event_version=1,
        predecessor_event_id=None,
        supersedes_event_ids=(),
        event_type=event_type,
        event_subtype={
            "acquisition": "business_combination",
            "divestiture": "business_sale",
            "equity_issuance": "public_offering",
            "debt_issuance": "refinancing",
            "debt_repayment": "refinancing",
            "buyback": "open_market",
            "dividend": "regular",
            "cash_accumulation": "operating_liquidity",
        }[event_type],
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        identity_components=(
            {"role": "program_id", "value": f"{event_type}-2026"},
            {"role": "approval_date", "value": "2026-01-01"},
            {"role": "security_class", "value": "common stock"},
        ),
        announcement_date="2026-01-01",
        execution_period=PERIOD,
        lifecycle_status=lifecycle_status,
        source_bindings=(
            {
                "binding_id": "source-binding:completion",
                "candidate_id": "candidate:completion",
                "decision_id": "decision:completion",
                "source_document_id": next(iter(facts_by_role.values())).source_document_id,
                "role_id": "completion",
            },
        ),
        fact_bindings=tuple(
            {
                "binding_id": f"fact-binding:{role}",
                "candidate_id": "candidate:completion",
                "decision_id": "decision:completion",
                "fact_id": fact.fact_id,
                "role_id": role,
            }
            for role, fact in facts_by_role.items()
        ),
        claim_bindings=(),
        rationale_statement_ids=(),
        related_commitment_ids=(),
        growth_classification="not_applicable",
        missing_evidence=(),
    )


def _run(
    policy_id: str,
    facts_by_role: dict[str, Fact],
    document: SourceDocument,
    *,
    event: CapitalAllocationEvent | None = None,
):
    policy = bridge_policy(policy_id)
    return run_capital_allocation_bridge(
        policy_id,
        event=event or _event(policy.event_type, facts_by_role),
        facts_by_role=facts_by_role,
        source_documents=(document,),
        as_of_date="2026-07-11",
        generated_at="2026-07-13T00:00:00Z",
    )


def test_bridge_registry_is_closed_and_contains_no_valuation_calculators() -> None:
    assert set(CAPITAL_ALLOCATION_BRIDGE_POLICIES) == {
        "acquisition_consideration_residual",
        "divestiture_consideration_residual",
        "equity_net_proceeds",
        "debt_issuance_incremental",
        "debt_repayment_cash_funded",
        "buyback_net_share_effect",
        "buyback_cash_per_share",
        "dividend_declared_aggregate",
        "gross_liquidity",
    }
    assert BRIDGE_POLICY_VERSION == "1.0.0"
    with pytest.raises(CapitalAllocationBridgeError, match="unregistered"):
        bridge_policy("free_form_dcf")


def test_equity_net_proceeds_normalizes_mixed_monetary_scales() -> None:
    document = _document()
    facts = {
        "gross_proceeds": _fact(
            "gross_proceeds", 1, "currency_billions", currency="USD", document=document
        ),
        "issuance_cost": _fact(
            "issuance_cost", 10, "currency_millions", currency="USD", document=document
        ),
    }
    result = _run("equity_net_proceeds", facts, document)
    assert result.value == 990_000_000
    assert result.unit == "currency_units"
    assert result.currency == "USD"
    assert result.calculator_id == BRIDGE_CALCULATOR_ID
    assert result.input_assumption_ids == ()
    ContractGraph(
        documents=(document,),
        facts=tuple(facts.values()),
        calculations=(result,),
    ).validate()


def test_acquisition_residual_reconciles_without_assuming_missing_components_are_zero() -> None:
    document = _document()
    values = {
        "purchase_price": 100,
        "cash_consideration": 80,
        "stock_consideration": 10,
        "debt_assumed": 5,
        "contingent_consideration": 5,
    }
    facts = {
        role: _fact(
            role,
            value,
            "currency_millions",
            currency="USD",
            document=document,
        )
        for role, value in values.items()
    }
    result = _run("acquisition_consideration_residual", facts, document)
    assert result.value == 0
    incomplete = dict(facts)
    incomplete.pop("contingent_consideration")
    with pytest.raises(CapitalAllocationBridgeError, match="roles do not match"):
        _run("acquisition_consideration_residual", incomplete, document)


def test_refinancing_bridge_separates_incremental_debt_from_rearranged_financing() -> None:
    document = _document()
    facts = {
        "principal_issued": _fact(
            "principal_issued", 100, "currency_millions", currency="USD", document=document
        ),
        "debt_refinanced": _fact(
            "debt_refinanced", 80, "currency_millions", currency="USD", document=document
        ),
    }
    result = _run("debt_issuance_incremental", facts, document)
    assert result.value == 20_000_000
    assert result.concept == "capital_allocation.incremental_debt"


def test_buyback_bridge_requires_sbc_and_other_issuance_before_net_share_effect() -> None:
    document = _document()
    facts = {
        "shares_repurched": _fact(
            "shares_repurched", 10, "shares", currency=None, document=document
        ),
        "sbc_shares_issued": _fact(
            "sbc_shares_issued", 6, "shares", currency=None, document=document
        ),
        "other_equity_shares_issued": _fact(
            "other_equity_shares_issued", 4, "shares", currency=None, document=document
        ),
    }
    result = _run("buyback_net_share_effect", facts, document)
    assert result.value == 0
    assert result.currency is None
    missing_sbc = {role: fact for role, fact in facts.items() if role != "sbc_shares_issued"}
    with pytest.raises(CapitalAllocationBridgeError, match="roles do not match"):
        _run("buyback_net_share_effect", missing_sbc, document)


def test_per_share_bridges_are_unit_safe() -> None:
    document = _document()
    dividend_facts = {
        "dividend_per_share_declared": _fact(
            "dividend_per_share_declared",
            0.25,
            "currency_per_share",
            currency="USD",
            document=document,
        ),
        "eligible_shares": _fact(
            "eligible_shares", 1_000_000, "shares", currency=None, document=document
        ),
    }
    dividend = _run("dividend_declared_aggregate", dividend_facts, document)
    assert dividend.value == 250_000
    assert dividend.unit == "currency_units"

    buyback_facts = {
        "cash_spent": _fact(
            "cash_spent", 50, "currency_millions", currency="USD", document=document
        ),
        "shares_repurched": _fact(
            "shares_repurched", 2_000_000, "shares", currency=None, document=document
        ),
    }
    cash_per_share = _run("buyback_cash_per_share", buyback_facts, document)
    assert cash_per_share.value == 25
    assert cash_per_share.unit == "currency_per_share"


def test_bridge_rejects_unreviewed_fact_cross_currency_and_noncomparable_period() -> None:
    document = _document()
    gross = _fact(
        "gross_proceeds", 100, "currency_millions", currency="USD", document=document
    )
    cost = _fact(
        "issuance_cost", 5, "currency_millions", currency="EUR", document=document
    )
    facts = {"gross_proceeds": gross, "issuance_cost": cost}
    with pytest.raises(CapitalAllocationBridgeError, match="one currency"):
        _run("equity_net_proceeds", facts, document)

    comparable_cost = replace(cost, currency="USD")
    event = _event("equity_issuance", {"gross_proceeds": gross})
    with pytest.raises(CapitalAllocationBridgeError, match="not reviewed"):
        _run(
            "equity_net_proceeds",
            {"gross_proceeds": gross, "issuance_cost": comparable_cost},
            document,
            event=event,
        )

    later_cost = replace(
        comparable_cost,
        period={"start": "2026-04-01", "end": "2026-06-30"},
    )
    with pytest.raises(CapitalAllocationBridgeError, match="comparable period"):
        _run(
            "equity_net_proceeds",
            {"gross_proceeds": gross, "issuance_cost": later_cost},
            document,
        )


def test_bridge_rejects_future_unofficial_forbidden_and_cancelled_evidence() -> None:
    future_document = _document(published_date="2026-07-12")
    facts = {
        "gross_proceeds": _fact(
            "gross_proceeds",
            100,
            "currency_millions",
            currency="USD",
            document=future_document,
        ),
        "issuance_cost": _fact(
            "issuance_cost",
            5,
            "currency_millions",
            currency="USD",
            document=future_document,
        ),
    }
    with pytest.raises(CapitalAllocationBridgeError, match="follows the cutoff"):
        _run("equity_net_proceeds", facts, future_document)

    unofficial = replace(future_document, published_date="2026-07-01", authority_level="secondary")
    unofficial_facts = {
        role: replace(fact, source_document_id=unofficial.document_id)
        for role, fact in facts.items()
    }
    with pytest.raises(CapitalAllocationBridgeError, match="official issuer source"):
        _run("equity_net_proceeds", unofficial_facts, unofficial)

    official = _document()
    shortcut_facts = {
        "gross_proceeds": _fact(
            "gross_proceeds",
            100,
            "currency_millions",
            currency="USD",
            document=official,
            concept="eps_accretion",
        ),
        "issuance_cost": _fact(
            "issuance_cost", 5, "currency_millions", currency="USD", document=official
        ),
    }
    with pytest.raises(CapitalAllocationBridgeError, match="forbidden result shortcut"):
        _run("equity_net_proceeds", shortcut_facts, official)

    cancelled = _event("equity_issuance", shortcut_facts, lifecycle_status="cancelled")
    with pytest.raises(CapitalAllocationBridgeError, match="lifecycle"):
        _run("equity_net_proceeds", shortcut_facts, official, event=cancelled)
