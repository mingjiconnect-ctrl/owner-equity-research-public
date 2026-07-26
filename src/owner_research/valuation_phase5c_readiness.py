"""Internal Phase 5C-5 successor-readiness compiler."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from .research_bundle_artifacts import (
    ResearchBundleArtifactError,
    load_research_bundle_artifacts,
)
from .validation import ContractGraph
from .valuation_accounting_policies import (
    METHOD_SUCCESSOR_REQUIRED_ROLES,
    METHODS,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
    ROUTING_ASSESSMENT_IDS,
    ROUTING_ASSESSMENT_REQUIRED_EVIDENCE,
    phase5c_policy_sha256,
)
from .valuation_accounting_types import (
    Phase5CReadinessResult,
    _stable_capital_snapshot_fact_ids,
    _validate_research_context,
    _validate_stable_capital_contracts,
)
from .valuation_equity_bridge import compile_equity_bridge


class Phase5CReadinessCompilationError(ValueError):
    """Raised when successor readiness cannot be compiled without inference."""


def _assessment(
    assessment_id: str,
    *,
    status: str,
    value: bool | None,
    rationale: str,
    evidence_fact_ids: set[str] | tuple[str, ...] = (),
    research_evidence_ids: set[str] | tuple[str, ...] = (),
    evidence_role_bindings: dict[str, set[str] | tuple[str, ...]] | None = None,
    reason_codes: set[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    bindings = {
        role: sorted((evidence_role_bindings or {}).get(role, ()))
        for role in ROUTING_ASSESSMENT_REQUIRED_EVIDENCE[assessment_id]
    }
    return {
        "status": status,
        "value": value,
        "rationale": rationale,
        "evidence_fact_ids": sorted(evidence_fact_ids),
        "research_evidence_ids": sorted(research_evidence_ids),
        "evidence_role_bindings": bindings,
        "reason_codes": sorted(reason_codes),
    }


def _module_object_ids(bundle: Any, module_type: str) -> set[str]:
    return {
        object_id
        for reference in bundle.module_references
        if reference["module_type"] == module_type
        for object_id in reference["object_ids"]
    }


def _stable_assessment(
    *,
    bridge: Any,
    footnote: Any,
    allocation: Any,
    claim: Any,
    candidate: Any,
    decision: Any,
) -> dict[str, Any]:
    snapshot_fact_ids = _stable_capital_snapshot_fact_ids(bridge.ledger_payload)
    status = "satisfied" if candidate.claim_role == "stable" else "unsatisfied"
    return _assessment(
        "stable_capital_structure",
        status=status,
        value=status == "satisfied",
        rationale=(
            "A named human reviewed the three-period capital structure, current debt footnote, "
            "capital-allocation coverage, counterevidence, and falsification condition."
        ),
        evidence_fact_ids={
            *snapshot_fact_ids,
            *footnote.fact_ids,
            *claim.supporting_fact_ids,
            *claim.counterevidence_fact_ids,
        },
        research_evidence_ids={
            footnote.review_id,
            allocation.review_id,
            claim.claim_id,
            candidate.candidate_id,
            decision.decision_id,
        },
        evidence_role_bindings={
            "three_comparable_annual_debt_cash_common_equity_snapshots": snapshot_fact_ids,
            "current_debt_liquidity_covenants_footnote_review": (footnote.review_id,),
            "current_capital_allocation_review": (allocation.review_id,),
            "named_human_confirmed_analytical_claim": (claim.claim_id,),
            "counterevidence_search": (claim.claim_id,),
            "falsification_condition": (claim.claim_id,),
        },
        reason_codes=() if status == "satisfied" else ("specialist_route_required",),
    )


def _select_stable_capital_package(
    *,
    graph: ContractGraph,
    bridge: Any,
) -> tuple[dict[str, Any] | None, tuple[Any | None, ...]]:
    reconciliation = bridge.method_view_result.reconciliation_result
    quality = bridge.method_view_result.quality_result
    bundles = [
        item
        for item in graph.research_bundles
        if item.bundle_id == reconciliation.research_bundle_id
    ]
    if len(bundles) != 1:
        raise Phase5CReadinessCompilationError("exact ResearchBundle is unavailable")
    bundle = bundles[0]
    footnote_ids = _module_object_ids(bundle, "footnote_review")
    allocation_ids = _module_object_ids(bundle, "capital_allocation_review")
    footnotes = [
        item
        for item in graph.footnote_reviews
        if item.review_id in footnote_ids and item.topic_code == "debt_liquidity_covenants"
    ]
    allocations = [
        item for item in graph.capital_allocation_reviews if item.review_id in allocation_ids
    ]
    if len(footnotes) != 1 or len(allocations) != 1:
        return None, (None, None, None, None, None)
    footnote = footnotes[0]
    allocation = allocations[0]
    candidates = {item.candidate_id: item for item in graph.analytical_claim_candidates}
    claims = {item.claim_id: item for item in graph.claims}
    valid: list[tuple[dict[str, Any], tuple[Any, ...]]] = []
    for decision in sorted(
        graph.analytical_claim_review_decisions, key=lambda item: item.decision_id
    ):
        candidate = candidates.get(decision.candidate_id)
        claim = claims.get(decision.output_claim_id or "")
        if (
            decision.decision != "confirmed"
            or candidate is None
            or claim is None
            or candidate.claim_role not in {"stable", "eroding"}
        ):
            continue
        assessment = _stable_assessment(
            bridge=bridge,
            footnote=footnote,
            allocation=allocation,
            claim=claim,
            candidate=candidate,
            decision=decision,
        )
        try:
            _validate_stable_capital_contracts(
                assessment=assessment,
                issuer_id=bridge.issuer_id,
                data_cutoff_date=bridge.data_cutoff_date,
                ledger_payload=bridge.ledger_payload,
                quality_result=quality,
                footnote_review=footnote,
                allocation_review=allocation,
                claim=claim,
                candidate=candidate,
                review_decision=decision,
            )
            _validate_research_context(
                graph=graph,
                issuer_id=bridge.issuer_id,
                data_cutoff_date=bridge.data_cutoff_date,
                reconciliation_result=reconciliation,
                quality_result=quality,
                footnote_review=footnote,
                allocation_review=allocation,
                stable_claim=claim,
                stable_candidate=candidate,
                stable_decision=decision,
            )
        except ValueError:
            continue
        valid.append((assessment, (footnote, allocation, claim, candidate, decision)))
    if len(valid) != 1:
        return None, (None, None, None, None, None)
    return valid[0]


def _routing_assessments(
    *,
    bridge: Any,
    stable: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    reconciliation = bridge.method_view_result.reconciliation_result
    classified = tuple(
        item for item in reconciliation.account_decisions if item.status == "classified"
    )
    separable = bool(reconciliation.account_decisions) and len(classified) == len(
        reconciliation.account_decisions
    )
    classification_fact_ids = {item.fact_id for item in classified}
    noa_check = reconciliation.checks["noa_nfo_common_equity"]
    noa_fact_ids = set(noa_check["fact_ids"])
    noa_status = noa_check["status"]
    credible_noa_status = (
        "satisfied"
        if noa_status == "reconciles_independently"
        else "blocked"
        if noa_status == "blocked"
        else "unsatisfied"
    )
    bridge_status = (
        "satisfied"
        if bridge.status == "complete" and bridge.kernel_request_compatible
        else "blocked"
        if bridge.status == "blocked"
        else "unsatisfied"
    )
    bridge_fact_ids = {
        fact_id
        for item in bridge.role_decisions
        for fact_id in (*item.evidence_fact_ids, *((item.fact_id,) if item.fact_id else ()))
    }
    assessments = {
        "required_data_complete": _assessment(
            "required_data_complete",
            status="unsatisfied",
            value=False,
            rationale="Phase 5C intentionally stops before assumptions and a complete request.",
            reason_codes=("required_data_incomplete_until_phase5e",),
        ),
        "stable_capital_structure": stable
        or _assessment(
            "stable_capital_structure",
            status="blocked",
            value=None,
            rationale="The complete typed stable-capital evidence package is unavailable.",
            reason_codes=("stable_capital_structure_evidence_missing",),
        ),
        "operating_financing_separable": _assessment(
            "operating_financing_separable",
            status="satisfied" if separable else "blocked",
            value=True if separable else None,
            rationale=(
                "Every selected account has a closed operating, financing, common-equity, or "
                "non-common-claim classification."
                if separable
                else "At least one selected account classification remains unresolved."
            ),
            evidence_fact_ids=classification_fact_ids if separable else (),
            research_evidence_ids=(reconciliation.fingerprint,) if separable else (),
            evidence_role_bindings={
                "closed_account_classification": classification_fact_ids,
                "noa_nfo_common_equity_reconciliation": noa_fact_ids,
            }
            if separable
            else {},
            reason_codes=() if separable else ("account_role_evidence_missing",),
        ),
        "credible_noa": _assessment(
            "credible_noa",
            status=credible_noa_status,
            value=(
                True
                if credible_noa_status == "satisfied"
                else False
                if credible_noa_status == "unsatisfied"
                else None
            ),
            rationale="The same-date NOA, NFO, and common-equity reconciliation was replayed.",
            evidence_fact_ids=noa_fact_ids if credible_noa_status != "blocked" else (),
            research_evidence_ids=(reconciliation.fingerprint,)
            if credible_noa_status != "blocked"
            else (),
            evidence_role_bindings={
                "noa_nfo_common_equity_reconciliation": noa_fact_ids
            }
            if credible_noa_status != "blocked"
            else {},
            reason_codes=(
                ()
                if credible_noa_status == "satisfied"
                else ("balance_sheet_by_construction",)
                if credible_noa_status == "unsatisfied"
                else ("balance_sheet_reconciliation_failed",)
            ),
        ),
        "credible_near_term_earnings": _assessment(
            "credible_near_term_earnings",
            status="pending_phase5d",
            value=None,
            rationale="Near-term earnings require Phase 5D assumption governance.",
            reason_codes=("phase5d_earnings_pending",),
        ),
        "equity_bridge_complete": _assessment(
            "equity_bridge_complete",
            status=bridge_status,
            value=(
                True
                if bridge_status == "satisfied"
                else False
                if bridge_status == "unsatisfied"
                else None
            ),
            rationale="The nine-role equity-bridge compiler and kernel-shape gate were replayed.",
            evidence_fact_ids=bridge_fact_ids,
            research_evidence_ids=(bridge.fingerprint,),
            evidence_role_bindings={"equity_bridge_compilation": (bridge.fingerprint,)},
            reason_codes=()
            if bridge_status == "satisfied"
            else bridge.reason_codes or ("bridge_role_coverage_incomplete",),
        ),
    }
    if set(assessments) != set(ROUTING_ASSESSMENT_IDS):
        raise Phase5CReadinessCompilationError("routing assessment registry drifted")
    return assessments


def _method_panels(
    *,
    bridge: Any,
    assessments: dict[str, dict[str, Any]],
    upstream: dict[str, str],
    specialist_route: str,
) -> dict[str, dict[str, Any]]:
    upstream_role_status = {
        "accounting_reconciliation": upstream["accounting_reconciliation"],
        "mckinsey_method_view": upstream["mckinsey_method_view"],
        "penman_method_view": upstream["penman_method_view"],
        "equity_bridge_complete": (
            "pass" if upstream["equity_bridge"] == "complete" else upstream["equity_bridge"]
        ),
    }
    assessment_status = {
        key: assessments[key]["status"]
        for key in (
            "stable_capital_structure",
            "operating_financing_separable",
            "credible_noa",
            "equity_bridge_complete",
        )
    }
    panels: dict[str, dict[str, Any]] = {}
    for method in METHODS:
        role_states: dict[str, str] = {}
        for role in METHOD_SUCCESSOR_REQUIRED_ROLES[method]:
            if role == "accounting_quality":
                role_states[role] = upstream[f"{method}_accounting_quality"]
            elif role in upstream_role_status:
                role_states[role] = upstream_role_status[role]
            else:
                role_states[role] = assessment_status[role]
            if role == "equity_bridge_complete" and assessment_status[role] != "satisfied":
                role_states[role] = assessment_status[role]
        satisfied = {
            role for role, status in role_states.items() if status in {"pass", "satisfied"}
        }
        missing = set(role_states).difference(satisfied)
        has_blocked = any(status == "blocked" for status in role_states.values())
        status = (
            "blocked"
            if specialist_route == "unresolved" or has_blocked
            else "specialist_required"
            if specialist_route != "none"
            else "partial"
            if missing
            else "ready_for_phase5d"
        )
        assessment_fact_ids = {
            fact_id
            for role in role_states
            if role in assessments
            for fact_id in assessments[role]["evidence_fact_ids"]
        }
        assessment_research_ids = {
            object_id
            for role in role_states
            if role in assessments
            for object_id in assessments[role]["research_evidence_ids"]
        }
        panels[method] = {
            "status": status,
            "satisfied_roles": sorted(satisfied),
            "missing_roles": sorted(missing),
            "evidence_fact_ids": sorted(assessment_fact_ids),
            "research_evidence_ids": sorted(
                {
                    *assessment_research_ids,
                    bridge.method_view_result.reconciliation_fingerprint,
                    bridge.method_view_result.quality_fingerprint,
                    bridge.method_view_result.fingerprint,
                    bridge.fingerprint,
                }
            ),
            "reason_codes": (
                []
                if status == "ready_for_phase5d"
                else [
                    "specialist_route_required"
                    if status == "specialist_required"
                    else "successor_role_missing"
                ]
            ),
        }
    return panels


def _compile_phase5c_readiness_result(
    *,
    bridge: Any,
    graph: ContractGraph,
) -> Phase5CReadinessResult:
    graph.validate()
    reconciliation = bridge.method_view_result.reconciliation_result
    quality = bridge.method_view_result.quality_result
    method_view = bridge.method_view_result
    specialist_route = reconciliation.phase5b_readiness_result.specialist_route
    stable_assessment, stable_objects = _select_stable_capital_package(
        graph=graph,
        bridge=bridge,
    )
    footnote, allocation, claim, candidate, decision = stable_objects
    if (
        stable_assessment is not None
        and stable_assessment["status"] == "unsatisfied"
        and specialist_route == "none"
    ):
        raise Phase5CReadinessCompilationError(
            "confirmed unstable capital structure requires replayed specialist routing"
        )
    context_sha, stable_sha, annual_bindings = _validate_research_context(
        graph=graph,
        issuer_id=bridge.issuer_id,
        data_cutoff_date=bridge.data_cutoff_date,
        reconciliation_result=reconciliation,
        quality_result=quality,
        footnote_review=footnote,
        allocation_review=allocation,
        stable_claim=claim,
        stable_candidate=candidate,
        stable_decision=decision,
    )
    assessments = _routing_assessments(bridge=bridge, stable=stable_assessment)
    upstream = {
        "accounting_reconciliation": reconciliation.status,
        "mckinsey_accounting_quality": quality.status_by_method["mckinsey"],
        "penman_accounting_quality": quality.status_by_method["penman"],
        "mckinsey_method_view": method_view.status_by_method["mckinsey"],
        "penman_method_view": method_view.status_by_method["penman"],
        "equity_bridge": bridge.status,
    }
    panels = _method_panels(
        bridge=bridge,
        assessments=assessments,
        upstream=upstream,
        specialist_route=specialist_route,
    )
    return Phase5CReadinessResult(
        issuer_id=bridge.issuer_id,
        data_cutoff_date=bridge.data_cutoff_date,
        phase5b_mapping_fingerprint=reconciliation.phase5b_mapping_fingerprint,
        phase5b_readiness_fingerprint=reconciliation.phase5b_readiness_fingerprint,
        reconciliation_fingerprint=reconciliation.fingerprint,
        reconciliation_result=reconciliation,
        quality_fingerprint=quality.fingerprint,
        quality_result=quality,
        method_view_fingerprint=method_view.fingerprint,
        method_view_result=method_view,
        equity_bridge_fingerprint=bridge.fingerprint,
        equity_bridge_result=bridge,
        stable_capital_footnote_review=footnote,
        stable_capital_allocation_review=allocation,
        stable_capital_claim=claim,
        stable_capital_claim_candidate=candidate,
        stable_capital_claim_review_decision=decision,
        validated_research_context_sha256=context_sha,
        stable_capital_evidence_closure_sha256=stable_sha,
        stable_capital_annual_bindings=annual_bindings,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        specialist_route=specialist_route,
        upstream_statuses=upstream,
        routing_assessments=assessments,
        method_panels=panels,
        validation_graph=graph,
    )


def assess_phase5c_readiness(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
) -> Phase5CReadinessResult:
    """Replay Phase 5C and compile separate McKinsey/Penman successor panels."""

    bridge = compile_equity_bridge(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
    )
    try:
        artifacts = load_research_bundle_artifacts(
            Path(bundle_artifact_directory),
            graph=graph,
        )
    except ResearchBundleArtifactError as exc:
        raise Phase5CReadinessCompilationError(
            "Bundle artifacts and ContractGraph do not replay"
        ) from exc
    bound_graph = replace(
        graph,
        manifests=tuple(
            artifacts.run_manifest if item.run_id == artifacts.run_manifest.run_id else item
            for item in graph.manifests
        ),
        research_bundles=(artifacts.bundle,),
    )
    return _compile_phase5c_readiness_result(bridge=bridge, graph=bound_graph)


__all__ = ()
