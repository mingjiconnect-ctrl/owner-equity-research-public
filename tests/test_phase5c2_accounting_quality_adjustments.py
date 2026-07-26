from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import pytest
from test_phase5c1_accounting_reconciliation import (
    KERNEL,
    _accounting_graph,
    _add_reviewed_claim,
    _artifacts,
)

import owner_research
from owner_research.contracts import AccountingQualityFinding
from owner_research.valuation_accounting_quality import (
    AccountingQualityCompilationError,
    compile_accounting_quality_adjustments,
)


def _quality_graph(
    sample_payloads: dict[str, dict],
    *,
    status: str = "confirmed",
    severity: str = "watch",
    category: str = "accruals",
    reviewed_claim: bool = True,
    evidence_in_ledger: bool = True,
):
    graph = _accounting_graph(sample_payloads)
    evidence_fact_id = (
        "fact:acme:phase5c1:total-assets" if evidence_in_ledger else graph.facts[0].fact_id
    )
    claim_ids: tuple[str, ...] = ()
    if status != "blocked":
        graph = _add_reviewed_claim(
            graph,
            statement=(
                "The reviewed accounting-quality evidence is classified under "
                f"{category} for the current period."
            ),
            fact_ids=(evidence_fact_id,),
            slug=f"quality-{category}-{status}-{severity}",
        )
        claim = graph.claims[-1]
        claim_ids = (claim.claim_id,)
        if not reviewed_claim:
            graph = replace(
                graph,
                analytical_claim_review_decisions=tuple(
                    item
                    for item in graph.analytical_claim_review_decisions
                    if item.output_claim_id != claim.claim_id
                ),
            )
    finding = AccountingQualityFinding(
        schema_version="1.0.0",
        finding_id=f"finding:acme:phase5c2:{category}:{status}:{severity}",
        issuer_id="issuer:acme",
        rule_id=f"phase5c2-{category}",
        rule_version="1.0.0",
        category=category,
        suggested_severity=severity,
        final_severity=severity if status != "blocked" else "informational",
        classification="temporary" if severity != "red_flag" else "structural",
        status=status,
        fact_ids=(evidence_fact_id,) if status != "blocked" else (),
        calculation_result_ids=(),
        claim_ids=claim_ids,
        override_claim_id=None,
        missing_evidence=("quality evidence unresolved",) if status == "blocked" else (),
    )
    review = graph.accounting_quality_reviews[0]
    return replace(
        graph,
        accounting_quality_findings=(finding,),
        accounting_quality_reviews=(replace(review, finding_ids=(finding.finding_id,)),),
    )


def _compile(graph, tmp_path: Path):
    return compile_accounting_quality_adjustments(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )


def test_quality_compiler_replays_reviewed_nonmaterial_finding(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    result = _compile(_quality_graph(sample_payloads), tmp_path)

    assert result.status == "pass"
    assert dict(result.status_by_method) == {"mckinsey": "pass", "penman": "pass"}
    assert result.kernel_gate_status == "pass"
    assert result.issue_decisions[0]["disposition"] == "nonmaterial"
    assert result.issue_decisions[0]["review_decision_id"].startswith("analytical-review:")
    assert result.unresolved_material_issue_ids == ()


def test_material_issue_blocks_only_its_registered_method_but_records_kernel_mismatch(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _quality_graph(
        sample_payloads,
        category="cash_conversion",
        severity="red_flag",
    )
    result = _compile(graph, tmp_path)

    assert result.status == "blocked"
    assert dict(result.status_by_method) == {
        "mckinsey": "blocked",
        "penman": "pass",
    }
    assert result.kernel_gate_status == "blocked"
    assert result.unresolved_material_issue_ids == (
        "finding:acme:phase5c2:cash_conversion:confirmed:red_flag",
    )
    assert dict(result.kernel_execution_compatibility_by_method) == {
        "mckinsey": False,
        "penman": False,
    }
    assert result.kernel_incompatibility_reason_codes["mckinsey"] == (
        "pinned_kernel_quality_gate_underblocks_mckinsey",
    )
    assert result.kernel_incompatibility_reason_codes["penman"] == (
        "pinned_kernel_global_gate_overblocks_penman",
    )


@pytest.mark.parametrize("finding_status", ("provisional", "blocked"))
def test_incomplete_quality_evidence_never_asserts_a_red_flag(
    sample_payloads: dict[str, dict], tmp_path: Path, finding_status: str
) -> None:
    graph = _quality_graph(
        sample_payloads,
        status=finding_status,
        severity="informational",
    )
    result = _compile(graph, tmp_path)

    assert result.status in {"partial", "blocked"}
    assert result.issue_decisions[0]["material"] is None
    assert result.issue_decisions[0]["resolved"] is None
    assert result.issue_decisions[0]["claim_id"] is None
    assert result.kernel_quality_issues == ()
    assert "accounting_quality_evidence_incomplete" in result.reason_codes


def test_quality_finding_without_confirmed_analytical_decision_is_rejected(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _quality_graph(sample_payloads, reviewed_claim=False)
    with pytest.raises(
        (AccountingQualityCompilationError, ValueError),
        match="confirmed analytical Decision|analytical human review",
    ):
        _compile(graph, tmp_path)


def test_quality_evidence_must_be_frozen_in_reconciliation(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _quality_graph(sample_payloads, evidence_in_ledger=False)
    with pytest.raises(
        AccountingQualityCompilationError,
        match="evidence is not frozen in reconciliation",
    ):
        _compile(graph, tmp_path)


def test_finding_severity_cannot_create_an_adjustment_amount(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _quality_graph(
        sample_payloads,
        category="goodwill_intangibles",
        severity="red_flag",
    )
    result = _compile(graph, tmp_path)

    assert all(
        item["concept"] != "method_adjustment_amount" for item in result.ledger_payload["facts"]
    )
    assert all(item.disposition != "compiled" for item in result.adjustment_decisions)


def test_subjective_adjustment_categories_remain_excluded(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    result = _compile(_accounting_graph(sample_payloads), tmp_path)

    decisions = {item.category: item for item in result.adjustment_decisions}
    assert decisions["other"].disposition == "excluded"
    assert decisions["other"].assumption_ids == ()
    assert all(item.category != "r_and_d" for item in result.adjustment_decisions)
    assert all(item.category != "brand_investment" for item in result.adjustment_decisions)
    assert all(
        item["concept"] != "method_adjustment_amount" for item in result.ledger_payload["facts"]
    )


def test_registered_same_source_lease_fact_compiles_zero_assumption_adjustment(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, financial_components=True)
    result = _compile(graph, tmp_path)

    lease = next(item for item in result.adjustment_decisions if item.category == "lease")
    amount = next(
        item for item in result.ledger_payload["facts"] if item["fact_id"] == lease.amount_fact_id
    )
    assert lease.disposition == "compiled"
    assert lease.assumption_ids == ()
    assert lease.target_concept == "invested_capital"
    assert lease.evidence_source_ids == ("doc:acme:2025-10k",)
    assert amount["concept"] == "method_adjustment_amount"
    assert amount["value"] == 5
    assert amount["raw"] is False
    assert amount["parent_fact_ids"] == ("fact:acme:phase5c1:operating-lease-liability",)


def test_compiler_is_internal_and_has_no_later_phase_surface() -> None:
    signature = inspect.signature(compile_accounting_quality_adjustments)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_accounting_quality_adjustments")
    assert not hasattr(owner_research, "compile_method_views")
    assert not hasattr(owner_research, "compile_equity_bridge")
    assert not hasattr(owner_research, "build_valuation_request")
    assert not hasattr(owner_research, "run_valuation_kernel")
