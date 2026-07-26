"""Internal Phase 5C-2 accounting-quality and adjustment compiler."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .contracts import (
    AccountingQualityFinding,
    AccountingQualityReview,
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Claim,
)
from .fingerprints import FrozenMap, to_json_value
from .validation import ContractGraph
from .valuation_accounting_policies import (
    ACCOUNTING_QUALITY_METHOD_APPLICABILITY,
    METHOD_ADJUSTMENT_CALCULATOR_POLICY,
    METHOD_ADJUSTMENT_CATEGORY_POLICIES,
    METHODS,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
    QUALITY_MAPPING_POLICIES,
    phase5c_policy_sha256,
)
from .valuation_accounting_reconciliation import (
    _load_context,
    _raw_roots,
    compile_accounting_reformulation,
)
from .valuation_accounting_types import (
    AccountingQualityCompilationResult,
    MethodAdjustmentDecision,
)


class AccountingQualityCompilationError(ValueError):
    """Raised when quality evidence cannot close without inference."""


def _selected_quality_contracts(
    *,
    bundle: Any,
    closure: dict[str, tuple[str, Any]],
) -> tuple[AccountingQualityReview, tuple[AccountingQualityFinding, ...]]:
    references = [
        reference
        for reference in bundle.module_references
        if reference["module_type"] == "accounting_quality_review"
    ]
    if len(references) != 1 or len(references[0]["object_ids"]) != 1:
        raise AccountingQualityCompilationError(
            "Bundle must select exactly one accounting-quality Review"
        )
    review_id = references[0]["object_ids"][0]
    selected = closure.get(review_id)
    if selected is None or selected[0] != "AccountingQualityReview":
        raise AccountingQualityCompilationError(
            "selected accounting-quality Review is outside the dependency closure"
        )
    review = selected[1]
    findings: list[AccountingQualityFinding] = []
    for finding_id in review.finding_ids:
        item = closure.get(finding_id)
        if item is None or item[0] != "AccountingQualityFinding":
            raise AccountingQualityCompilationError(
                "accounting-quality Finding is outside the dependency closure"
            )
        findings.append(item[1])
    return review, tuple(sorted(findings, key=lambda item: item.finding_id))


def _reviewed_claim_chain(
    *,
    finding: AccountingQualityFinding,
    closure: dict[str, tuple[str, Any]],
    cutoff: str,
) -> tuple[Claim, AnalyticalClaimCandidate, AnalyticalClaimReviewDecision]:
    claim_ids = (
        (finding.override_claim_id,)
        if finding.override_claim_id is not None
        else finding.claim_ids
    )
    if len(claim_ids) != 1:
        raise AccountingQualityCompilationError(
            f"Finding {finding.finding_id} requires one unambiguous reviewed Claim"
        )
    selected = closure.get(claim_ids[0])
    if selected is None or selected[0] != "Claim":
        raise AccountingQualityCompilationError(
            f"Finding {finding.finding_id} Claim is outside the dependency closure"
        )
    claim: Claim = selected[1]
    decisions = [
        item
        for kind, item in closure.values()
        if kind == "AnalyticalClaimReviewDecision"
        and item.output_claim_id == claim.claim_id
        and item.decision == "confirmed"
    ]
    if len(decisions) != 1:
        raise AccountingQualityCompilationError(
            f"Finding {finding.finding_id} lacks one confirmed analytical Decision"
        )
    decision = decisions[0]
    candidate_item = closure.get(decision.candidate_id)
    if candidate_item is None or candidate_item[0] != "AnalyticalClaimCandidate":
        raise AccountingQualityCompilationError(
            f"Finding {finding.finding_id} analytical Candidate is missing"
        )
    candidate = candidate_item[1]
    reviewed_date = datetime.fromisoformat(decision.reviewed_at.replace("Z", "+00:00")).date()
    if (
        claim.issuer_id != finding.issuer_id
        or candidate.issuer_id != finding.issuer_id
        or decision.issuer_id != finding.issuer_id
        or decision.candidate_fingerprint != candidate.fingerprint
        or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
        or not decision.reviewer_id.startswith("human:")
        or reviewed_date > date.fromisoformat(cutoff)
        or date.fromisoformat(claim.as_of_date) > date.fromisoformat(cutoff)
        or not claim.counterevidence_search_note
        or not claim.falsification_condition
        or not set(finding.fact_ids).issubset(claim.supporting_fact_ids)
    ):
        raise AccountingQualityCompilationError(
            f"Finding {finding.finding_id} reviewed Claim chain does not replay"
        )
    return claim, candidate, decision


def _issue_decision(
    *,
    finding: AccountingQualityFinding,
    closure: dict[str, tuple[str, Any]],
    cutoff: str,
) -> tuple[
    dict[str, Any],
    tuple[Claim, AnalyticalClaimCandidate, AnalyticalClaimReviewDecision] | None,
]:
    evidence_state = (
        "confirmed_red_flag"
        if finding.status == "confirmed" and finding.final_severity == "red_flag"
        else finding.final_severity
        if finding.status == "confirmed"
        else finding.status
    )
    mapping = QUALITY_MAPPING_POLICIES.get(evidence_state)
    if mapping is None:
        raise AccountingQualityCompilationError(
            f"Finding {finding.finding_id} has an unregistered evidence state"
        )
    disposition = {
        "confirmed_red_flag": "material_unresolved",
        "cleared": "resolved",
        "watch": "nonmaterial",
        "informational": "nonmaterial",
        "provisional": "provisional",
        "blocked": "blocked",
    }[evidence_state]
    material = (
        finding.final_severity == "red_flag"
        if mapping.material_source == "reviewed_final_severity"
        else mapping.material
    )
    chain = None
    if disposition in {"material_unresolved", "resolved", "nonmaterial"}:
        chain = _reviewed_claim_chain(finding=finding, closure=closure, cutoff=cutoff)
    reasons = (
        ("accounting_quality_evidence_incomplete",)
        if disposition in {"provisional", "blocked"}
        else ()
    )
    return (
        {
            "finding_id": finding.finding_id,
            "finding_fingerprint": finding.fingerprint,
            "finding_status": finding.status,
            "final_severity": finding.final_severity,
            "evidence_state": evidence_state,
            "category": finding.category,
            "disposition": disposition,
            "material": material,
            "resolved": mapping.resolved,
            "evidence_fact_ids": list(finding.fact_ids),
            "claim_id": chain[0].claim_id if chain else None,
            "review_decision_id": chain[2].decision_id if chain else None,
            "reason_codes": list(reasons),
        },
        chain,
    )


def _adjustment_decisions(
    ledger: dict[str, dict[str, Any]],
) -> tuple[tuple[MethodAdjustmentDecision, ...], tuple[dict[str, Any], ...]]:
    target = next(
        (
            item
            for item in ledger.values()
            if item["concept"] == "invested_capital"
            and item["raw"] is False
            and item["period_start"] is None
        ),
        None,
    )
    if target is None:
        raise AccountingQualityCompilationError(
            "accounting reconciliation lacks the invested-capital target"
        )
    current_end = target["period_end"]
    decisions: list[MethodAdjustmentDecision] = []
    outputs: list[dict[str, Any]] = []
    for category, policy in sorted(METHOD_ADJUSTMENT_CATEGORY_POLICIES.items()):
        source_facts = tuple(
            sorted(
                (
                    item
                    for item in ledger.values()
                    if item["concept"] in policy.permitted_source_concepts
                    and item["period_end"] == current_end
                ),
                key=lambda item: item["fact_id"],
            )
        )
        if not source_facts:
            continue
        roots = tuple(
            sorted(
                {
                    root
                    for item in source_facts
                    for root in _raw_roots(item["fact_id"], ledger)
                }
            )
        )
        source_ids = tuple(sorted({item["source_id"] for item in source_facts}))
        source_fact_ids = tuple(item["fact_id"] for item in source_facts)
        base = {
            "method": "mckinsey",
            "adjustment_id": f"adjustment:phase5c:{category}:{current_end}",
            "adjustment_group_id": f"adjustment-group:phase5c:{category}:{current_end}",
            "category": category,
            "source_fact_ids": source_fact_ids,
            "root_fact_ids": roots,
            "evidence_source_ids": source_ids,
            "assumption_ids": (),
        }
        can_compile = (
            category == "lease"
            and not policy.requires_phase5d_judgment
            and len(source_ids) == 1
            and {
                (item["period_start"], item["period_end"], item["as_of_date"])
                for item in source_facts
            }
            == {(target["period_start"], target["period_end"], target["as_of_date"])}
            and all(
                item["currency"] == target["currency"]
                and item["unit"] == target["unit"]
                for item in source_facts
            )
            and not set(roots).intersection(_raw_roots(target["fact_id"], ledger))
        )
        if not can_compile:
            decisions.append(
                MethodAdjustmentDecision(
                    **base,
                    disposition="excluded",
                    target_fact_id=None,
                    target_concept=None,
                    target_bridge_role=None,
                    amount_fact_id=None,
                    calculation_id=None,
                    calculator_id=None,
                    calculator_version=None,
                    calculator_code_sha256=None,
                    rationale=(
                        "The evidence requires Phase 5D judgment or a later bridge/dilution "
                        "decision and cannot produce a Phase 5C-2 amount."
                    ),
                    reason_codes=(),
                )
            )
            continue
        calculator = METHOD_ADJUSTMENT_CALCULATOR_POLICY
        amount_id = f"derived:phase5c:method-adjustment:{category}:{current_end}"
        value = sum(float(item["value"]) for item in source_facts)
        amount = {
            "fact_id": amount_id,
            "concept": "method_adjustment_amount",
            "value": int(value) if value.is_integer() else value,
            "unit": target["unit"],
            "category": "evidence",
            "source_id": source_ids[0],
            "source_location": f"{calculator.calculator_id}@{calculator.calculator_version}",
            "as_of_date": target["as_of_date"],
            "currency": target["currency"],
            "period_start": target["period_start"],
            "period_end": target["period_end"],
            "confidence": min(
                (item["confidence"] for item in source_facts),
                key={"low": 0, "medium": 1, "high": 2}.get,
            ),
            "raw": False,
            "parent_fact_ids": list(source_fact_ids),
            "derivation": calculator.derivation_label,
            "equity_bridge_role": None,
        }
        outputs.append(amount)
        decisions.append(
            MethodAdjustmentDecision(
                **base,
                disposition="compiled",
                target_fact_id=target["fact_id"],
                target_concept="invested_capital",
                target_bridge_role=None,
                amount_fact_id=amount_id,
                calculation_id=f"calculation:phase5c:method-adjustment:{category}:{current_end}",
                calculator_id=calculator.calculator_id,
                calculator_version=calculator.calculator_version,
                calculator_code_sha256=calculator.calculator_code_sha256,
                rationale="Official same-period lease evidence supports a zero-Assumption amount.",
                reason_codes=(),
            )
        )
    return tuple(decisions), tuple(outputs)


def _kernel_quality_gate(
    *, kernel_repository: Path, issues: tuple[dict[str, Any], ...]
) -> tuple[str, tuple[str, ...]]:
    script = r"""
import json
import sys
from owner_valuation.validation import AccountingQualityIssue, accounting_quality_gate

payload = json.load(sys.stdin)
issues = tuple(AccountingQualityIssue(**item) for item in payload)
result = accounting_quality_gate(issues)
json.dump({"status": result.status, "unresolved": result.unresolved_material_issues}, sys.stdout)
"""
    env = os.environ.copy()
    kernel_src = str(kernel_repository.resolve() / "src")
    env["PYTHONPATH"] = kernel_src + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(issues, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        payload = json.loads(completed.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise AccountingQualityCompilationError(
            "pinned kernel accounting-quality gate failed"
        ) from exc
    return payload["status"], tuple(payload["unresolved"])


def compile_accounting_quality_adjustments(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
) -> AccountingQualityCompilationResult:
    """Compile current quality evidence and zero-Assumption adjustment amounts."""

    reconciliation = compile_accounting_reformulation(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
    )
    bundle, _, closure = _load_context(Path(bundle_artifact_directory), graph)
    if (
        bundle.bundle_id != reconciliation.research_bundle_id
        or bundle.bundle_fingerprint != reconciliation.research_bundle_fingerprint
        or bundle.dependency_closure_sha256 != reconciliation.dependency_closure_sha256
    ):
        raise AccountingQualityCompilationError(
            "accounting reconciliation does not bind the canonical Bundle"
        )
    review, findings = _selected_quality_contracts(bundle=bundle, closure=closure)
    fiscal_period = closure.get(review.fiscal_period_id)
    if (
        review.issuer_id != bundle.issuer_id
        or fiscal_period is None
        or fiscal_period[0] != "FiscalPeriod"
        or fiscal_period[1].issuer_id != bundle.issuer_id
        or max(fiscal_period[1].quarter_end, fiscal_period[1].cumulative_end)
        > bundle.data_cutoff_date
    ):
        raise AccountingQualityCompilationError(
            "accounting-quality Review period or issuer does not match the Bundle"
        )
    reconciliation_payload = to_json_value(reconciliation.ledger_payload)
    ledger = {item["fact_id"]: dict(item) for item in reconciliation_payload["facts"]}
    decisions: list[dict[str, Any]] = []
    for finding in findings:
        if finding.issuer_id != bundle.issuer_id:
            raise AccountingQualityCompilationError("quality Finding issuer mismatch")
        if not set(finding.fact_ids).issubset(ledger):
            raise AccountingQualityCompilationError(
                f"Finding {finding.finding_id} evidence is not frozen in reconciliation"
            )
        decision, _ = _issue_decision(
            finding=finding,
            closure=closure,
            cutoff=bundle.data_cutoff_date,
        )
        decisions.append(decision)
    adjustment_decisions, outputs = _adjustment_decisions(ledger)
    for output in outputs:
        ledger[output["fact_id"]] = output
    reviewed_decisions = tuple(
        item
        for item in decisions
        if item["disposition"] in {"material_unresolved", "resolved", "nonmaterial"}
    )
    kernel_issues = tuple(
        {
            "issue_id": item["finding_id"],
            "category": item["category"],
            "material": item["material"],
            "resolved": item["resolved"],
            "evidence_fact_ids": item["evidence_fact_ids"],
        }
        for item in reviewed_decisions
    )
    kernel_status, unresolved = _kernel_quality_gate(
        kernel_repository=Path(kernel_repository), issues=kernel_issues
    )
    expected_unresolved = tuple(
        item["finding_id"]
        for item in reviewed_decisions
        if item["material"] and not item["resolved"]
    )
    if kernel_status not in {"pass", "blocked"} or unresolved != expected_unresolved:
        raise AccountingQualityCompilationError(
            "pinned kernel accounting-quality gate did not round-trip"
        )
    missing = tuple(
        sorted(
            {
                *review.missing_evidence,
                *(gap for finding in findings for gap in finding.missing_evidence),
            }
        )
    )
    incomplete = review.status != "complete" or any(
        item["disposition"] in {"provisional", "blocked"} for item in decisions
    )
    status_by_method: dict[str, str] = {}
    for method in METHODS:
        applicable = [
            item
            for item in decisions
            if method in ACCOUNTING_QUALITY_METHOD_APPLICABILITY[item["category"]]
        ]
        status_by_method[method] = (
            "blocked"
            if review.status == "blocked"
            or any(
                item["disposition"] in {"material_unresolved", "blocked"}
                for item in applicable
            )
            else "partial"
            if review.status == "partial"
            or missing
            or any(item["disposition"] == "provisional" for item in applicable)
            else "pass"
        )
    status = (
        "blocked"
        if kernel_status == "blocked"
        or review.status == "blocked"
        or any(item["disposition"] == "blocked" for item in decisions)
        else "partial"
        if incomplete or missing
        else "pass"
    )
    reasons = tuple(
        sorted(
            {
                *(
                    ("accounting_quality_material_unresolved",)
                    if expected_unresolved
                    else ()
                ),
                *(
                    ("accounting_quality_evidence_incomplete",)
                    if incomplete or missing
                    else ()
                ),
            }
        )
    )
    route_effect = {
        "mckinsey": "not_blocked_by_quality_gate",
        "penman": (
            "blocked_by_quality_gate"
            if kernel_status == "blocked"
            else "not_blocked_by_quality_gate"
        ),
    }
    compatibility = {
        method: (
            (status_by_method[method] == "blocked")
            == (route_effect[method] == "blocked_by_quality_gate")
        )
        for method in METHODS
    }
    incompatibility = {
        method: (
            ()
            if compatibility[method]
            else (
                ("pinned_kernel_quality_gate_underblocks_mckinsey",)
                if method == "mckinsey"
                else ("pinned_kernel_global_gate_overblocks_penman",)
            )
        )
        for method in METHODS
    }
    payload = {
        **reconciliation_payload,
        "facts": sorted(ledger.values(), key=lambda item: item["fact_id"]),
    }
    return AccountingQualityCompilationResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        reconciliation_fingerprint=reconciliation.fingerprint,
        reconciliation_result=reconciliation,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        accounting_quality_review_id=review.review_id,
        accounting_quality_review_fingerprint=review.fingerprint,
        accounting_quality_review_status=review.status,
        accounting_quality_review=review,
        accounting_quality_findings=findings,
        ledger_payload=FrozenMap(payload),
        adjustment_decisions=adjustment_decisions,
        expected_finding_ids=review.finding_ids,
        issue_decisions=tuple(decisions),
        kernel_quality_issues=kernel_issues,
        kernel_gate_status=kernel_status,
        kernel_gate_scope="global",
        kernel_route_effect_by_method=FrozenMap(route_effect),
        kernel_execution_compatibility_by_method=FrozenMap(compatibility),
        kernel_incompatibility_reason_codes=FrozenMap(incompatibility),
        unresolved_material_issue_ids=expected_unresolved,
        status=status,
        status_by_method=FrozenMap(status_by_method),
        missing_evidence=missing,
        reason_codes=reasons,
    )
