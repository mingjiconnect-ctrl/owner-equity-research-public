from __future__ import annotations

import inspect
import os
from dataclasses import replace
from pathlib import Path

import pytest
from phase4e2_support import complete_phase4e_graph

import owner_research
from owner_research.analytical_claims import review_analytical_claim_candidate
from owner_research.fingerprints import canonical_sha256, freeze
from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.valuation_accounting_reconciliation import (
    AccountingReconciliationError,
    _account_classification_review_statement,
    _economic_binding_template,
    _formula_inclusion_review_statement,
    compile_accounting_reformulation,
)
from owner_research.valuation_accounting_types import _economic_claim_review_statement

KERNEL = Path(
    os.environ.get(
        "OWNER_VALUATION_REPO",
        str(Path(__file__).parents[2] / "owner-valuation-kernel"),
    )
)


def _fact(
    seed,
    slug: str,
    concept: str,
    value: float,
    *,
    start: str | None = None,
    end: str = "2025-12-31",
    currency: str = "USD",
):
    return replace(
        seed,
        fact_id=f"fact:acme:phase5c1:{slug}",
        concept=concept,
        value=value,
        value_type="number",
        unit="currency_millions",
        currency=currency,
        period={"start": start, "end": end},
        confidence="high",
        derivation=None,
        parent_fact_ids=(),
        source_locator=f"10-K:{slug}",
    )


def _add_reviewed_claim(graph, *, statement: str, fact_ids: tuple[str, ...], slug: str):
    base = graph.analytical_claim_candidates[0]
    supporting = tuple(
        {
            "binding_id": f"binding:phase5c1:{slug}:{index}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for index, fact_id in enumerate(sorted(fact_ids))
    )
    candidate = replace(
        base,
        candidate_id=f"analytical-candidate:phase5c1:{slug}",
        issuer_id="issuer:acme",
        as_of_date="2025-12-31",
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        proposed_statement=statement,
        proposed_confidence="high",
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        generation_method="manual",
        counterevidence_search_note="Reviewed the filing for contradictory classifications.",
        falsification_condition="A later official filing disproves this exact relationship.",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": supporting,
                "counterevidence_bindings": (),
            }
        ),
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:phase5c1-accounting-reviewer",
        reviewed_at="2026-01-15T12:00:00Z",
        rationale="The exact evidence and counterevidence search were reviewed.",
    )
    assert claim is not None
    review = graph.business_quality_reviews[0]
    coverage = dict(review.coverage)
    coverage["confirmed_claim_count"] += 1
    return replace(
        graph,
        claims=(*graph.claims, claim),
        analytical_claim_candidates=(*graph.analytical_claim_candidates, candidate),
        analytical_claim_review_decisions=(
            *graph.analytical_claim_review_decisions,
            decision,
        ),
        business_quality_reviews=(
            replace(
                review,
                claim_ids=tuple(sorted({*review.claim_ids, claim.claim_id})),
                analytical_claim_review_decision_ids=tuple(
                    sorted(
                        {
                            *review.analytical_claim_review_decision_ids,
                            decision.decision_id,
                        }
                    )
                ),
                coverage=coverage,
            ),
        ),
    )


def _accounting_graph(
    sample_payloads: dict[str, dict],
    *,
    total_assets: float = 180.0,
    omit: frozenset[str] = frozenset(),
    add_component_overlap: bool = False,
    total_equity_currency: str = "USD",
    comprehensive_concept: str = "comprehensive_income_attributable_to_common",
    flow_start: str = "2025-01-01",
    owner_values: dict[str, float] | None = None,
    include_nci: bool = False,
    review_nci: bool = True,
    financial_components: bool = False,
):
    graph = complete_phase4e_graph(sample_payloads)
    official = replace(
        graph.documents[0],
        source_url="https://www.sec.gov/Archives/edgar/data/1/acme-20251231.htm",
    )
    seed = replace(graph.facts[0], source_document_id=official.document_id)
    owner_values = owner_values or {}
    facts = {
        "total_assets": _fact(seed, "total-assets", "total_assets", total_assets),
        "total_liabilities": _fact(seed, "total-liabilities", "total_liabilities", 80.0),
        "total_equity": _fact(
            seed,
            "total-equity",
            "total_equity",
            100.0,
            currency=total_equity_currency,
        ),
        "beginning_common_equity": _fact(
            seed,
            "beginning-common-equity",
            "common_equity",
            85.0 if include_nci else 90.0,
            end="2024-12-31",
        ),
        "operating_assets": _fact(seed, "operating-assets", "operating_assets", 200.0),
        "operating_liabilities": _fact(
            seed,
            "operating-liabilities",
            "operating_liabilities",
            50.0,
        ),
        "financial_obligations": _fact(
            seed,
            "financial-obligations",
            "financial_obligations",
            50.0,
        ),
        "financial_assets": _fact(seed, "financial-assets", "financial_assets", 0.0),
        "comprehensive_income": _fact(
            seed,
            "comprehensive-income",
            comprehensive_concept,
            10.0,
            start=flow_start,
        ),
        "common_dividends": _fact(
            seed,
            "common-dividends",
            "common_dividends",
            owner_values.get("common_dividends", 0.0),
            start=flow_start,
        ),
        "common_share_repurchases": _fact(
            seed,
            "common-share-repurchases",
            "common_share_repurchases",
            owner_values.get("common_share_repurchases", 0.0),
            start=flow_start,
        ),
        "common_equity_issuance_proceeds": _fact(
            seed,
            "common-equity-issuance",
            "common_equity_issuance_proceeds",
            owner_values.get("common_equity_issuance_proceeds", 0.0),
            start=flow_start,
        ),
        "equity_settled_sbc_owner_contribution": _fact(
            seed,
            "sbc-owner-contribution",
            "equity_settled_sbc_owner_contribution",
            owner_values.get("equity_settled_sbc_owner_contribution", 0.0),
            start=flow_start,
        ),
        "other_common_owner_distributions": _fact(
            seed,
            "other-owner-distributions",
            "other_common_owner_distributions",
            owner_values.get("other_common_owner_distributions", 0.0),
            start=flow_start,
        ),
        "other_common_owner_contributions": _fact(
            seed,
            "other-owner-contributions",
            "other_common_owner_contributions",
            owner_values.get("other_common_owner_contributions", 0.0),
            start=flow_start,
        ),
    }
    if include_nci:
        facts["noncontrolling_interest"] = _fact(
            seed,
            "noncontrolling-interest",
            "noncontrolling_interest",
            5.0,
        )
    if financial_components:
        facts.pop("financial_obligations")
        facts["interest_bearing_debt"] = _fact(
            seed,
            "interest-bearing-debt",
            "interest_bearing_debt",
            45.0,
        )
        facts["operating_lease_liability"] = _fact(
            seed,
            "operating-lease-liability",
            "operating_lease_liability",
            5.0,
        )
    if add_component_overlap:
        facts["accounts_receivable"] = _fact(
            seed,
            "accounts-receivable",
            "accounts_receivable",
            25.0,
        )
    included = tuple(item for key, item in facts.items() if key not in omit)
    update = replace(
        graph.quarterly_updates[0],
        fact_ids=tuple(
            sorted({*graph.quarterly_updates[0].fact_ids, *(item.fact_id for item in included)})
        ),
    )
    graph = replace(
        graph,
        documents=(official, *graph.documents[1:]),
        facts=(*graph.facts, *included),
        quarterly_updates=(update,),
    )
    included_fact_ids = {item.fact_id for item in included}
    total_equity_id = facts["total_equity"].fact_id
    total_liabilities_id = facts["total_liabilities"].fact_id
    financial_obligation_ids = tuple(
        facts[key].fact_id
        for key in (
            ("interest_bearing_debt", "operating_lease_liability")
            if financial_components
            else ("financial_obligations",)
        )
    )
    nci_ids = (facts["noncontrolling_interest"].fact_id,) if include_nci else ()
    if include_nci and review_nci:
        statement = _account_classification_review_statement(
            issuer_id="issuer:acme",
            fact_id=nci_ids[0],
            concept="noncontrolling_interest",
            account_role="non_common_claim",
            measurement_end="2025-12-31",
            perimeter_disposition={
                "total_equity": "included",
                "reported_liabilities": "excluded",
                "financial_obligations": "excluded",
            },
        )
        graph = _add_reviewed_claim(
            graph,
            statement=statement,
            fact_ids=nci_ids,
            slug="classification-nci",
        )
    for purpose, input_role, fact_ids, support_ids, status, slug in (
        (
            "common_equity",
            "included_non_common_equity_claims",
            nci_ids,
            tuple(sorted({total_equity_id, *nci_ids})),
            "included_in_total_equity" if nci_ids else "none_identified_after_review",
            "formula-common-equity",
        ),
        (
            "adjusted_total_liabilities",
            "equity_classified_non_common_claims",
            nci_ids,
            tuple(sorted({total_liabilities_id, *nci_ids})),
            "outside_reported_liabilities" if nci_ids else "none_identified_after_review",
            "formula-adjusted-liabilities",
        ),
        (
            "net_financial_obligations",
            "nfo_non_common_equity_claims",
            nci_ids,
            tuple(sorted({*financial_obligation_ids, *nci_ids})),
            "not_in_reported_liabilities" if nci_ids else "none_identified_after_review",
            "formula-nfo",
        ),
    ):
        if not set(support_ids).issubset(included_fact_ids):
            continue
        statement = _formula_inclusion_review_statement(
            issuer_id="issuer:acme",
            purpose=purpose,
            input_role=input_role,
            measurement_end="2025-12-31",
            fact_ids=fact_ids,
            support_fact_ids=support_ids,
            inclusion_status=status,
        )
        graph = _add_reviewed_claim(
            graph,
            statement=statement,
            fact_ids=support_ids,
            slug=slug,
        )
    economic_roots = tuple(
        sorted(
            {
                facts["operating_assets"].fact_id,
                facts["operating_liabilities"].fact_id,
                facts["financial_assets"].fact_id,
                *financial_obligation_ids,
            }
        )
    )
    economic_groups = (
        (
            (
                "method_base",
                tuple(
                    sorted(
                        {
                            facts["operating_assets"].fact_id,
                            facts["operating_liabilities"].fact_id,
                            facts["financial_assets"].fact_id,
                        }
                    )
                ),
            ),
            ("debt", (facts["interest_bearing_debt"].fact_id,)),
            ("lease_liability", (facts["operating_lease_liability"].fact_id,)),
        )
        if financial_components
        else (("method_base", economic_roots),)
    )
    for economic_identity, economic_fact_ids in economic_groups:
        template = _economic_binding_template(
            issuer_id="issuer:acme",
            measurement_end="2025-12-31",
            economic_identity=economic_identity,
            root_fact_ids=economic_fact_ids,
        )
        if set(economic_fact_ids).issubset(included_fact_ids):
            graph = _add_reviewed_claim(
                graph,
                statement=_economic_claim_review_statement(freeze(template)),
                fact_ids=economic_fact_ids,
                slug=f"economic-{economic_identity}",
            )
    if nci_ids and set(nci_ids).issubset(included_fact_ids):
        template = _economic_binding_template(
            issuer_id="issuer:acme",
            measurement_end="2025-12-31",
            economic_identity="noncontrolling_interest",
            root_fact_ids=nci_ids,
        )
        graph = _add_reviewed_claim(
            graph,
            statement=_economic_claim_review_statement(freeze(template)),
            fact_ids=nci_ids,
            slug="economic-nci",
        )
    return graph


def _artifacts(graph, path: Path) -> Path:
    build = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    write_research_bundle_artifacts(graph, build, output_directory=path)
    return path


def test_compile_accounting_reformulation_replays_all_three_controls(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads)
    result = compile_accounting_reformulation(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert result.status == "pass"
    assert result.reason_codes == ()
    assert {item.purpose for item in result.fact_decisions} == {
        "common_equity",
        "adjusted_total_liabilities",
        "net_operating_assets",
        "net_financial_obligations",
        "invested_capital",
        "net_distributions_to_owners",
    }
    assert {item["status"] for item in result.checks.values()} == {"reconciles_independently"}
    facts = list(result.ledger_payload["facts"])
    assert (
        next(
            item["value"]
            for item in facts
            if item["concept"] == "common_equity" and item["period_end"] == "2025-12-31"
        )
        == 100
    )
    assert next(item["value"] for item in facts if item["concept"] == "net_operating_assets") == 150
    assert (
        next(item["value"] for item in facts if item["concept"] == "net_financial_obligations")
        == 50
    )
    assert (
        next(item["value"] for item in facts if item["concept"] == "net_distributions_to_owners")
        == 0
    )
    assert result.phase5b_mapping_result.fingerprint == result.phase5b_mapping_fingerprint


@pytest.mark.parametrize(
    ("omit", "match"),
    (
        (frozenset({"total_equity"}), "total assets, total liabilities, and total equity"),
        (frozenset({"common_dividends"}), "owner transaction"),
        (frozenset({"comprehensive_income"}), "comprehensive-income"),
        (frozenset({"financial_obligations"}), "financial_obligation"),
    ),
)
def test_compiler_fails_closed_on_missing_accounting_evidence(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
    omit: frozenset[str],
    match: str,
) -> None:
    graph = _accounting_graph(sample_payloads, omit=omit)
    with pytest.raises((AccountingReconciliationError, ValueError), match=match):
        compile_accounting_reformulation(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_total_equity_cannot_be_replaced_by_common_equity_and_total_liabilities_is_not_nfo(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(
        sample_payloads,
        omit=frozenset({"total_equity", "financial_obligations"}),
    )
    with pytest.raises(AccountingReconciliationError):
        compile_accounting_reformulation(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_aggregate_and_component_account_roots_are_not_double_counted(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, add_component_overlap=True)
    with pytest.raises(AccountingReconciliationError, match="aggregate and components"):
        compile_accounting_reformulation(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_cross_currency_perimeter_fact_is_blocked(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, total_equity_currency="EUR")
    with pytest.raises(AccountingReconciliationError, match="reporting-currency"):
        compile_accounting_reformulation(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_balance_sheet_residual_is_reported_blocked_not_plugged(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, total_assets=181.0)
    result = compile_accounting_reformulation(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert result.status == "blocked"
    assert result.checks["balance_sheet"]["difference"] == 1.0
    assert "balance_sheet_reconciliation_failed" in result.reason_codes
    assert all(item["concept"] != "residual_plug" for item in result.ledger_payload["facts"])


def test_reviewed_noncontrolling_interest_closes_one_common_equity_perimeter(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, include_nci=True)
    result = compile_accounting_reformulation(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    facts = list(result.ledger_payload["facts"])
    assert result.status == "partial"
    assert result.checks["balance_sheet"]["status"] == "reconciles_by_construction"
    assert (
        next(
            item["value"]
            for item in facts
            if item["concept"] == "common_equity" and item["period_end"] == "2025-12-31"
        )
        == 95
    )
    assert (
        next(item["value"] for item in facts if item["concept"] == "adjusted_total_liabilities")
        == 85
    )
    nci = next(
        item for item in result.account_decisions if item.concept == "noncontrolling_interest"
    )
    assert nci.classification_basis == "reviewed_claim"
    assert nci.perimeter_disposition == {
        "total_equity": "included",
        "reported_liabilities": "excluded",
        "financial_obligations": "excluded",
    }


def test_noncommon_claim_without_named_human_classification_is_blocked(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, include_nci=True, review_nci=False)
    with pytest.raises(AccountingReconciliationError, match="named-human reviewed classification"):
        compile_accounting_reformulation(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_owner_transaction_signs_are_policy_derived_not_caller_authored(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(
        sample_payloads,
        owner_values={
            "common_dividends": 3.0,
            "common_share_repurchases": 4.0,
            "common_equity_issuance_proceeds": 2.0,
            "equity_settled_sbc_owner_contribution": 1.0,
        },
    )
    result = compile_accounting_reformulation(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    owner_fact = next(
        item
        for item in result.ledger_payload["facts"]
        if item["concept"] == "net_distributions_to_owners"
    )
    assert owner_fact["value"] == 4
    assert result.checks["clean_surplus"]["status"] == "blocked"


def test_net_income_cannot_substitute_for_attributable_comprehensive_income(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, comprehensive_concept="net_income")
    with pytest.raises(AccountingReconciliationError, match="comprehensive-income"):
        compile_accounting_reformulation(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_clean_surplus_requires_a_consecutive_beginning_equity_date(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, flow_start="2025-02-01")
    with pytest.raises(AccountingReconciliationError, match="consecutive beginning"):
        compile_accounting_reformulation(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_compiler_remains_internal_and_has_no_later_phase_controls() -> None:
    signature = inspect.signature(compile_accounting_reformulation)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_accounting_reformulation")
    assert not hasattr(owner_research, "compile_accounting_quality")
    assert not hasattr(owner_research, "compile_method_views")
    assert not hasattr(owner_research, "compile_equity_bridge")
    assert not hasattr(owner_research, "run_valuation_kernel")
