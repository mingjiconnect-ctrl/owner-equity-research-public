from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_phase5_v1_owner_equity_research import (
    _ordinary_result,
    _ordinary_runtime,
    _request,
    _result_values,
)

from owner_research.contracts import QuarterlyUpdate
from owner_research.owner_equity_research import (
    ExecutionStepReceipt,
    OfficialResearchPhaseResult,
    OwnerEquityResearchError,
    OwnerEquityResearchInputReceipt,
    OwnerEquityResearchResult,
    PhaseReceipt,
    PhaseStatus,
    QuarterlyPhaseResult,
    ResearchIntent,
    run_owner_equity_research,
)
from owner_research.owner_equity_runtime import build_runtime_dependencies


def _quarterly_update(issuer_id: str, as_of_date: str) -> QuarterlyUpdate:
    return QuarterlyUpdate(
        schema_version="1.0.0",
        update_id=f"quarterly-update:{issuer_id}:causal-chain",
        issuer_id=issuer_id,
        as_of_date=as_of_date,
        current_period_id="period:current",
        comparison_period_id="period:comparison",
        status="complete",
        comparability={"status": "comparable", "reasons": []},
        fact_ids=("fact:quarterly:revenue",),
        calculation_result_ids=("calculation:quarterly:change",),
        reconciliation_ids=(),
        what_changed_claim_ids=("claim:quarterly:change",),
        why_it_changed_claim_ids=("claim:quarterly:why",),
        temporary_or_structural_claim_ids=("claim:quarterly:duration",),
        guidance_change_claim_ids=("claim:quarterly:guidance",),
        long_term_thesis_impact_claim_ids=("claim:quarterly:thesis",),
        impact_on_valuation_assumptions_claim_ids=(),
        valuation_assumption_review_required=False,
        confidence="high",
        missing_evidence=(),
        red_flags=(),
    )


def test_same_value_request_from_two_runs_cannot_rebind_official_phase(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, runtime = _ordinary_runtime(sample_payloads, monkeypatch, tmp_path)
    first_request = _request(graph)
    second_request = replace(first_request)
    assert second_request == first_request
    assert second_request is not first_request

    dependencies = build_runtime_dependencies(runtime)
    first = run_owner_equity_research(
        request=first_request,
        dependencies=dependencies,
    )
    second = run_owner_equity_research(
        request=second_request,
        dependencies=dependencies,
    )
    assert second.official_research is not None
    values = _result_values(first)
    values["official_research"] = second.official_research

    with pytest.raises(OwnerEquityResearchError, match="another execution"):
        OwnerEquityResearchResult.create(**values)


def test_structurally_equal_child_receipt_cannot_rebind_another_upstream_run(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _graph, _runtime, research_request, research_result = _ordinary_result(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    source = research_result.official_research
    assert source is not None
    request = replace(research_request, intent=ResearchIntent.QUARTERLY)
    input_receipt = OwnerEquityResearchInputReceipt.from_request(request)
    official_receipt = PhaseReceipt.create(
        phase="official_research_freeze",
        input_receipt=input_receipt,
        upstream_receipts=(),
        authorities=(source.research_input, source.source_index, source.security_scope),
    )
    official = OfficialResearchPhaseResult(
        status=PhaseStatus.COMPLETED,
        issuer_id=request.issuer_id,
        data_cutoff_date=request.data_cutoff_date,
        receipt=official_receipt,
        security_scope=source.security_scope,
        research_input=source.research_input,
        source_index=source.source_index,
        price_blind=True,
    )
    update = _quarterly_update(request.issuer_id, request.data_cutoff_date)
    quarterly_receipt = PhaseReceipt.create(
        phase="quarterly",
        input_receipt=input_receipt,
        upstream_receipts=(official_receipt,),
        authorities=(update,),
    )
    quarterly = QuarterlyPhaseResult(
        status=PhaseStatus.COMPLETED,
        issuer_id=request.issuer_id,
        data_cutoff_date=request.data_cutoff_date,
        receipt=quarterly_receipt,
        quarterly_result=update,
    )
    values: dict[str, object] = {
        "status": PhaseStatus.COMPLETED,
        "input_receipt": input_receipt,
        "official_research": official,
        "quarterly": quarterly,
        "futu_nonprice": None,
        "price_blind": None,
        "market_reference": None,
        "kernel": None,
        "synthesis": None,
        "score": None,
        "market_expectations": None,
        "report": None,
        "publication": None,
        "audit": None,
        "quarantine_receipt": None,
        "trace": (
            ExecutionStepReceipt(1, "official_research_freeze", PhaseStatus.COMPLETED),
            ExecutionStepReceipt(2, "quarterly", PhaseStatus.COMPLETED),
        ),
        "issue_codes": (),
    }
    baseline = OwnerEquityResearchResult.create(**values)
    assert baseline.status is PhaseStatus.COMPLETED

    other_official_receipt = replace(official_receipt)
    assert other_official_receipt == official_receipt
    assert other_official_receipt is not official_receipt
    rebound_receipt = PhaseReceipt.create(
        phase="quarterly",
        input_receipt=input_receipt,
        upstream_receipts=(other_official_receipt,),
        authorities=(update,),
    )
    assert rebound_receipt == quarterly_receipt
    assert rebound_receipt is not quarterly_receipt
    values["quarterly"] = replace(quarterly, receipt=rebound_receipt)

    with pytest.raises(OwnerEquityResearchError, match="causal upstreams were rebound"):
        OwnerEquityResearchResult.create(**values)


@pytest.mark.parametrize(
    ("status", "issues"),
    (
        (PhaseStatus.PARTIAL, ("caller_reclassified_partial",)),
        (PhaseStatus.COMPLETED, ("caller_injected_issue",)),
    ),
)
def test_result_factory_rejects_caller_authored_outcome_reclassification(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    status: PhaseStatus,
    issues: tuple[str, ...],
) -> None:
    _graph, _runtime, _request_value, result = _ordinary_result(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    values = _result_values(result)
    values["status"] = status
    values["issue_codes"] = issues

    with pytest.raises(OwnerEquityResearchError, match="not derived from its exact route"):
        OwnerEquityResearchResult.create(**values)


def test_partial_expectations_session_is_the_preferred_futu_evidence_bundle() -> None:
    session = object()
    result = object.__new__(OwnerEquityResearchResult)
    object.__setattr__(
        result,
        "market_expectations",
        SimpleNamespace(
            status=PhaseStatus.PARTIAL,
            session=session,
            evidence_bundle=session,
        ),
    )
    object.__setattr__(result, "market_reference", None)
    object.__setattr__(result, "futu_nonprice", None)

    assert result.futu_evidence_bundle is session
