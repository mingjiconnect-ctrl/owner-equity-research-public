from __future__ import annotations

from dataclasses import replace

import pytest
from phase4a_support import valid_phase4a_graph

from owner_research.mechanism_diagnostics import (
    DIAGNOSTIC_POLICIES,
    MechanismDiagnosticError,
    diagnostic_policy,
    run_diagnostic,
)
from owner_research.validation import ContractGraph

ISSUER_SCOPE = {
    "scope_type": "issuer_wide",
    "segment_definition_ids": [],
    "business_unit": None,
    "product_service": None,
    "geography": None,
    "customer_group": None,
    "channel": None,
}


def _series(graph):
    prior = replace(
        graph.facts[0],
        fact_id="fact:acme:price:2024",
        concept="average_price",
        value=100.0,
        period={"start": "2024-01-01", "end": "2024-12-31"},
    )
    current = replace(
        prior,
        fact_id="fact:acme:price:2025",
        value=110.0,
        period={"start": "2025-01-01", "end": "2025-12-31"},
    )
    prior_period = replace(
        graph.periods[0],
        period_id="period:acme:2024-q4",
        fiscal_year=2024,
        quarter_start="2024-10-01",
        quarter_end="2024-12-31",
        cumulative_start="2024-01-01",
        cumulative_end="2024-12-31",
        ttm_start="2024-01-01",
    )
    return current, prior, graph.periods[0], prior_period


def test_registry_roles_belong_to_all_ten_mechanism_policies() -> None:
    assert {item.mechanism for item in DIAGNOSTIC_POLICIES.values()} == {
        "switching_cost",
        "network_effect",
        "scale_cost_advantage",
        "brand_pricing_power",
        "intellectual_property",
        "regulatory_license",
        "distribution",
        "data_learning",
        "efficient_scale",
        "process_execution",
    }
    for policy_id in DIAGNOSTIC_POLICIES:
        policy = diagnostic_policy(policy_id)
        assert policy.version == "1.0.0"
        assert policy.calculator_id == "owner-research-mechanism-diagnostics"
        assert policy.role_id
        assert policy.polarity in {"support", "counterevidence"}
        assert len(policy.input_roles) == len(policy.input_unit_rules)
        assert policy.period_semantics in {"same_period", "successive_periods"}
        assert policy.allowed_scope_types == frozenset({"issuer_wide", "segment_specific"})
        assert policy.minimum_observations >= 1
        assert "roic" in policy.forbidden_shortcuts


def test_growth_is_deterministic_assumption_free_and_fingerprinted(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    current, prior, current_period, prior_period = _series(graph)
    result = run_diagnostic(
        "price_mix_growth",
        facts_by_role={"current": current, "prior": prior},
        periods_by_role={"current": current_period, "prior": prior_period},
        scope=ISSUER_SCOPE,
        segment_snapshots=(),
        generated_at="2026-02-16T04:00:00Z",
    )
    assert result.value == pytest.approx(0.1)
    assert result.unit == "ratio"
    assert not result.input_assumption_ids
    replay = run_diagnostic(
        "price_mix_growth",
        facts_by_role={"current": current, "prior": prior},
        periods_by_role={"current": current_period, "prior": prior_period},
        scope=ISSUER_SCOPE,
        segment_snapshots=(),
        generated_at="2026-02-17T04:00:00Z",
    )
    assert replay.calculation_id == result.calculation_id
    assert replay.input_fingerprint == result.input_fingerprint
    assert replay.output_fingerprint == result.output_fingerprint
    assert len(result.code_sha256) == 64
    ContractGraph(
        documents=graph.documents,
        facts=(current, prior),
        periods=(current_period, prior_period),
        calculations=(result,),
    ).validate()


def test_difference_complement_ratio_and_per_unit_primitives(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    current, prior, current_period, prior_period = _series(graph)
    difference = run_diagnostic(
        "retention_change",
        facts_by_role={"current": current, "prior": prior},
        periods_by_role={"current": current_period, "prior": prior_period},
        scope=ISSUER_SCOPE,
        segment_snapshots=(),
        generated_at="2026-02-16T04:00:00Z",
    )
    assert difference.value == 10
    retention = replace(current, fact_id="fact:retention", value=0.92, unit="ratio", currency=None)
    churn = run_diagnostic(
        "churn_complement",
        facts_by_role={"rate": retention},
        periods_by_role={"rate": current_period},
        scope=ISSUER_SCOPE,
        segment_snapshots=(),
        generated_at="2026-02-16T04:00:00Z",
    )
    assert churn.value == pytest.approx(0.08)
    locations = replace(
        current,
        fact_id="fact:locations",
        concept="locations",
        value=10,
        unit="locations",
        currency=None,
    )
    per_location = run_diagnostic(
        "revenue_per_location",
        facts_by_role={"numerator": current, "denominator": locations},
        periods_by_role={"numerator": current_period, "denominator": current_period},
        scope=ISSUER_SCOPE,
        segment_snapshots=(),
        generated_at="2026-02-16T04:00:00Z",
    )
    assert per_location.unit == "currency_per_location"


def test_direct_only_free_policy_and_valuation_inputs_are_rejected(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    current, prior, current_period, prior_period = _series(graph)
    with pytest.raises(MechanismDiagnosticError, match="unregistered"):
        diagnostic_policy("free_form")
    with pytest.raises(MechanismDiagnosticError, match="direct evidence"):
        run_diagnostic(
            "ip_direct_evidence",
            facts_by_role={},
            periods_by_role={},
            scope=ISSUER_SCOPE,
            segment_snapshots=(),
            generated_at="2026-02-16T04:00:00Z",
        )
    nopat = replace(current, concept="NOPAT")
    with pytest.raises(MechanismDiagnosticError, match="valuation concepts"):
        run_diagnostic(
            "price_mix_growth",
            facts_by_role={"current": nopat, "prior": prior},
            periods_by_role={"current": current_period, "prior": prior_period},
            scope=ISSUER_SCOPE,
            segment_snapshots=(),
            generated_at="2026-02-16T04:00:00Z",
        )


def test_scope_period_unit_and_issuer_mismatches_fail_closed(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    current, prior, current_period, prior_period = _series(graph)
    common = dict(
        policy_id="price_mix_growth",
        facts_by_role={"current": current, "prior": prior},
        periods_by_role={"current": current_period, "prior": prior_period},
        segment_snapshots=(),
        generated_at="2026-02-16T04:00:00Z",
    )
    with pytest.raises(MechanismDiagnosticError, match="scope"):
        run_diagnostic(
            **common,
            scope={**ISSUER_SCOPE, "scope_type": "product_market", "product_service": "X"},
        )
    with pytest.raises(MechanismDiagnosticError, match="input roles"):
        run_diagnostic(**{**common, "facts_by_role": {"current": current}}, scope=ISSUER_SCOPE)
    foreign = replace(prior, issuer_id="issuer:other")
    with pytest.raises(MechanismDiagnosticError, match="issuer"):
        run_diagnostic(
            **{**common, "facts_by_role": {"current": current, "prior": foreign}},
            scope=ISSUER_SCOPE,
        )
    wrong_unit = replace(prior, unit="currency_thousands")
    with pytest.raises(MechanismDiagnosticError, match="same unit"):
        run_diagnostic(
            **{**common, "facts_by_role": {"current": current, "prior": wrong_unit}},
            scope=ISSUER_SCOPE,
        )
    wrong_period = replace(prior_period, cumulative_end="2023-12-31")
    with pytest.raises(MechanismDiagnosticError, match="not represented"):
        run_diagnostic(
            **{
                **common,
                "periods_by_role": {"current": current_period, "prior": wrong_period},
            },
            scope=ISSUER_SCOPE,
        )


def test_external_context_is_not_a_diagnostic_input_domain() -> None:
    parameters = run_diagnostic.__annotations__
    assert "ContextObservation" not in repr(parameters)
    assert "context" not in " ".join(parameters)


def test_segment_scope_requires_each_period_fact_assignment(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    current, prior, current_period, prior_period = _series(graph)
    segment_id = graph.segment_definitions[0].segment_id
    current_snapshot = replace(
        graph.segment_snapshots[0],
        metric_assignments=(
            {
                "segment_id": segment_id,
                "fact_id": current.fact_id,
                "metric_role": "revenue",
                "presentation_order": 0,
            },
        ),
    )
    prior_snapshot = replace(
        current_snapshot,
        snapshot_id="segment-snapshot:acme:2024",
        fiscal_period_id=prior_period.period_id,
        metric_assignments=(
            {
                "segment_id": segment_id,
                "fact_id": prior.fact_id,
                "metric_role": "revenue",
                "presentation_order": 0,
            },
        ),
    )
    scope = {
        **ISSUER_SCOPE,
        "scope_type": "segment_specific",
        "segment_definition_ids": [segment_id],
    }
    result = run_diagnostic(
        "price_mix_growth",
        facts_by_role={"current": current, "prior": prior},
        periods_by_role={"current": current_period, "prior": prior_period},
        scope=scope,
        segment_snapshots=(current_snapshot, prior_snapshot),
        generated_at="2026-02-16T04:00:00Z",
    )
    assert result.value == pytest.approx(0.1)
    with pytest.raises(MechanismDiagnosticError, match="period segment scope"):
        run_diagnostic(
            "price_mix_growth",
            facts_by_role={"current": current, "prior": prior},
            periods_by_role={"current": current_period, "prior": prior_period},
            scope=scope,
            segment_snapshots=(current_snapshot,),
            generated_at="2026-02-16T04:00:00Z",
        )
