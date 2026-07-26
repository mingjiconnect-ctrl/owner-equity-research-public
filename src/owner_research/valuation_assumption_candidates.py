"""Internal Phase 5D-1 compiler for price-blind valuation-assumption Candidates."""

from __future__ import annotations

import math
import re
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

from .contracts import ValuationAssumptionCandidate
from .fingerprints import canonical_sha256
from .research_bundle_artifacts import (
    ResearchBundleArtifactError,
    load_research_bundle_artifacts,
)
from .research_bundle_validation import dependency_closure
from .units import normalize_value
from .validation import ContractGraph, ContractGraphError
from .valuation_assumption_types import (
    AssumptionCandidateCompilationResult,
    AssumptionCandidateProposal,
    PriceBlindReferenceClosure,
)
from .valuation_handoff_policies import (
    ASSUMPTION_CANDIDATE_POLICY_ID,
    ASSUMPTION_CANDIDATE_POLICY_VERSION,
    assumption_evidence_policy_sha256,
    assumption_slot_policy,
    assumption_slot_policy_sha256,
    empty_supplemental_reference_closure_sha256,
)
from .valuation_handoff_validation import candidate_evidence_graph_sha256
from .valuation_phase5c_readiness import assess_phase5c_readiness


class AssumptionCandidateCompilationError(ValueError):
    """Raised when a Candidate proposal cannot be compiled without inference."""


ROLE_CONTRACT_TYPES = {
    "mapped_historical_fact": frozenset({"Fact", "CalculationResult"}),
    "reviewed_management_guidance": frozenset({"ManagementReview"}),
    "reviewed_business_quality": frozenset({"BusinessQualityReview"}),
    "reviewed_accounting_quality": frozenset({"AccountingQualityReview"}),
    "reviewed_capital_allocation": frozenset({"CapitalAllocationReview"}),
    "debt_cost": frozenset({"Fact", "CalculationResult"}),
    "capital_structure": frozenset({"Fact", "CalculationResult"}),
    "tax_rate": frozenset({"Fact", "CalculationResult"}),
    "counterevidence": frozenset({"Fact", "CalculationResult", "Claim"}),
    "falsification": frozenset({"Fact", "CalculationResult", "Claim"}),
    "limitation": frozenset({"Fact", "CalculationResult", "Claim"}),
}


def _bundle_roots(bundle: Any) -> tuple[str, ...]:
    return tuple(
        object_id
        for reference in bundle.module_references
        for object_id in reference["object_ids"]
    )


def _binding_id(payload: dict[str, str]) -> str:
    return f"assumption-evidence:{canonical_sha256(payload)[:20]}"


def _candidate_id(*, bundle: Any, proposal: AssumptionCandidateProposal) -> str:
    digest = canonical_sha256(
        {
            "issuer_id": bundle.issuer_id,
            "data_cutoff_date": bundle.data_cutoff_date,
            "bundle_fingerprint": bundle.bundle_fingerprint,
            "proposal": proposal.to_dict(),
        }
    )
    return f"valuation-candidate:{bundle.issuer_id}:{digest[:20]}"


def _validate_horizon(proposal: AssumptionCandidateProposal, *, cutoff: str) -> None:
    try:
        slot = assumption_slot_policy(proposal.assumption_slot_id)
        end = date.fromisoformat(str(proposal.horizon["end_date"]))
        start_raw = proposal.horizon.get("start_date")
        start = date.fromisoformat(str(start_raw)) if start_raw is not None else None
    except (KeyError, TypeError, ValueError) as exc:
        raise AssumptionCandidateCompilationError("proposal horizon or slot is invalid") from exc
    if proposal.horizon.get("kind") != slot.horizon_kind:
        raise AssumptionCandidateCompilationError("proposal horizon kind does not match its slot")
    if start is not None and start > end:
        raise AssumptionCandidateCompilationError("proposal horizon starts after it ends")
    if end <= date.fromisoformat(cutoff):
        raise AssumptionCandidateCompilationError("forecast horizon must follow the data cutoff")
    year_match = re.search(r"\.(?P<year>[0-9]{4})\.", proposal.assumption_slot_id)
    if year_match is None:
        year_match = re.search(r"\.(?P<year>[0-9]{4})$", proposal.assumption_slot_id)
    if year_match is not None and end.year != int(year_match.group("year")):
        raise AssumptionCandidateCompilationError("proposal horizon year does not match its slot")


def _numeric_evidence_matches(
    proposal: AssumptionCandidateProposal,
    *,
    evidence_items: tuple[Any, ...],
) -> bool:
    numeric = [
        item
        for item in evidence_items
        if getattr(item, "value_type", None) == "number"
        and getattr(item, "unit", None) is not None
    ]
    if len(numeric) != 1:
        return False
    item = numeric[0]
    if item.currency != proposal.currency:
        return False
    try:
        return normalize_value(item.value, item.unit) == normalize_value(
            proposal.value, proposal.unit
        )
    except (TypeError, ValueError):
        return False


def _compile_with_readiness(
    *,
    graph: ContractGraph,
    bundle: Any,
    readiness: Any,
    proposals: tuple[AssumptionCandidateProposal, ...],
    supplemental_reference_closure: PriceBlindReferenceClosure | None,
) -> AssumptionCandidateCompilationResult:
    if not proposals:
        raise AssumptionCandidateCompilationError("at least one Candidate proposal is required")
    if any(
        (
            graph.valuation_assumption_candidates,
            graph.valuation_assumption_review_decisions,
            graph.market_reference_snapshots,
            graph.valuation_handoffs,
        )
    ):
        raise AssumptionCandidateCompilationError(
            "Candidate compilation requires an unanchored Phase 5D graph"
        )
    if any(item.authority_level == "market_reference" for item in graph.documents):
        raise AssumptionCandidateCompilationError(
            "market-reference evidence cannot enter Candidate compilation"
        )
    closure_hash = (
        supplemental_reference_closure.fingerprint
        if supplemental_reference_closure is not None
        else empty_supplemental_reference_closure_sha256()
    )
    if supplemental_reference_closure is not None and (
        supplemental_reference_closure.target_issuer_id != bundle.issuer_id
        or supplemental_reference_closure.data_cutoff_date != bundle.data_cutoff_date
    ):
        raise AssumptionCandidateCompilationError(
            "supplemental closure does not match the Bundle context"
        )
    bound_graph = replace(
        graph,
        price_blind_reference_closures=(
            (supplemental_reference_closure,)
            if supplemental_reference_closure is not None
            else ()
        ),
    )
    research_closure = dependency_closure(bound_graph, _bundle_roots(bundle))
    supplemental_facts = {
        item.fact_id: item
        for item in (
            supplemental_reference_closure.facts
            if supplemental_reference_closure is not None
            else ()
        )
    }
    mapped_ledger_ids = {
        item["fact_id"] for item in readiness.equity_bridge_result.ledger_payload["facts"]
    }
    candidates: list[ValuationAssumptionCandidate] = []
    seen_slots: set[str] = set()
    for proposal in sorted(proposals, key=lambda item: item.assumption_slot_id):
        if proposal.assumption_slot_id in seen_slots:
            raise AssumptionCandidateCompilationError("proposal set repeats an assumption slot")
        seen_slots.add(proposal.assumption_slot_id)
        try:
            slot = assumption_slot_policy(proposal.assumption_slot_id)
        except KeyError as exc:
            raise AssumptionCandidateCompilationError(str(exc)) from exc
        if readiness.method_panels[slot.method_scope]["status"] != "ready_for_phase5d":
            raise AssumptionCandidateCompilationError(
                f"{slot.method_scope} is not ready for Phase 5D Candidate compilation"
            )
        if not isinstance(proposal.value, (int, float)) or not math.isfinite(proposal.value):
            raise AssumptionCandidateCompilationError("proposal value must be a finite number")
        _validate_horizon(proposal, cutoff=bundle.data_cutoff_date)
        bindings: list[dict[str, str]] = []
        evidence_items: list[Any] = []
        for requested in proposal.evidence:
            payload = requested.to_dict()
            allowed_types = ROLE_CONTRACT_TYPES.get(requested.slot_evidence_role)
            if requested.evidence_domain == "supplemental_price_blind":
                allowed_types = frozenset({"Fact"})
                item = supplemental_facts.get(requested.object_id)
            else:
                matching = research_closure.get(requested.object_id)
                item = matching[1] if matching is not None else None
                if matching is not None and matching[0] != requested.contract_type:
                    item = None
            if (
                item is None
                or allowed_types is None
                or requested.contract_type not in allowed_types
                or requested.slot_evidence_role not in slot.allowed_evidence_roles
            ):
                raise AssumptionCandidateCompilationError(
                    "proposal evidence is not eligible for its typed slot role"
                )
            if requested.slot_evidence_role == "mapped_historical_fact":
                mapped_id = (
                    f"derived:{requested.object_id}"
                    if requested.contract_type == "CalculationResult"
                    else requested.object_id
                )
                if mapped_id not in mapped_ledger_ids:
                    raise AssumptionCandidateCompilationError(
                        "historical evidence was not mapped into the replayed FactLedger"
                    )
            binding = {"binding_id": _binding_id(payload), **payload}
            bindings.append(binding)
            evidence_items.append(item)
        if len({item["binding_id"] for item in bindings}) != len(bindings):
            raise AssumptionCandidateCompilationError("proposal repeats an evidence edge")
        bindings.sort(key=lambda item: item["binding_id"])
        if proposal.generation_method == "deterministic" and not _numeric_evidence_matches(
            proposal,
            evidence_items=tuple(evidence_items),
        ):
            raise AssumptionCandidateCompilationError(
                "deterministic proposal value does not round-trip one numeric evidence item"
            )
        candidate = ValuationAssumptionCandidate(
            schema_version="2.0.0",
            candidate_id=_candidate_id(bundle=bundle, proposal=proposal),
            issuer_id=bundle.issuer_id,
            data_cutoff_date=bundle.data_cutoff_date,
            candidate_policy_id=ASSUMPTION_CANDIDATE_POLICY_ID,
            candidate_policy_version=ASSUMPTION_CANDIDATE_POLICY_VERSION,
            research_bundle_id=bundle.bundle_id,
            research_bundle_fingerprint=bundle.bundle_fingerprint,
            research_bundle_dependency_sha256=bundle.dependency_closure_sha256,
            supplemental_reference_closure_sha256=closure_hash,
            assumption_slot_id=proposal.assumption_slot_id,
            method_scope=slot.method_scope,
            kernel_concept=slot.kernel_concept,
            value=proposal.value,
            unit=proposal.unit,
            currency=proposal.currency,
            horizon=proposal.horizon,
            scenario=proposal.scenario,
            rationale=proposal.rationale.strip(),
            evidence_bindings=tuple(bindings),
            generation_method=proposal.generation_method,
            evidence_graph_sha256="0" * 64,
            validation_status="eligible",
            validation_issues=(),
        )
        candidate = replace(
            candidate,
            evidence_graph_sha256=candidate_evidence_graph_sha256(bound_graph, candidate),
        )
        candidates.append(candidate)
    candidate_graph = replace(
        bound_graph,
        valuation_assumption_candidates=tuple(candidates),
    )
    try:
        candidate_graph.validate()
    except ContractGraphError as exc:
        raise AssumptionCandidateCompilationError(
            "compiled Candidates do not replay in the ContractGraph"
        ) from exc
    return AssumptionCandidateCompilationResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        research_bundle_dependency_sha256=bundle.dependency_closure_sha256,
        phase5c_readiness_fingerprint=readiness.fingerprint,
        supplemental_reference_closure_sha256=closure_hash,
        assumption_slot_policy_sha256=assumption_slot_policy_sha256(),
        assumption_evidence_policy_sha256=assumption_evidence_policy_sha256(),
        candidates=tuple(candidates),
    )


def compile_valuation_assumption_candidates(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
    proposals: tuple[AssumptionCandidateProposal, ...],
    supplemental_reference_closure: PriceBlindReferenceClosure | None = None,
) -> AssumptionCandidateCompilationResult:
    """Strictly replay Phase 5C and compile unreviewed, price-blind Candidates in memory."""

    try:
        graph.validate()
        artifacts = load_research_bundle_artifacts(
            Path(bundle_artifact_directory),
            graph=graph,
        )
    except (ContractGraphError, ResearchBundleArtifactError) as exc:
        raise AssumptionCandidateCompilationError(
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
    readiness = assess_phase5c_readiness(
        bundle_artifact_directory=Path(bundle_artifact_directory),
        graph=bound_graph,
        kernel_repository=Path(kernel_repository),
    )
    return _compile_with_readiness(
        graph=bound_graph,
        bundle=artifacts.bundle,
        readiness=readiness,
        proposals=tuple(proposals),
        supplemental_reference_closure=supplemental_reference_closure,
    )


__all__ = ()
