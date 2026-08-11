"""Validation-only Phase 5A gates for the valuation handoff boundary."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import replace
from datetime import date, datetime
from decimal import Decimal
from pathlib import PurePosixPath
from typing import Any

from .component_lock import file_sha256
from .contracts import (
    Contract,
    MarketReferenceSnapshot,
    ValuationAssumptionCandidate,
    ValuationHandoff,
)
from .fingerprints import canonical_sha256
from .research_bundle_validation import dependency_closure
from .units import normalize_value, unit_spec
from .valuation_current_share_evidence import (
    CurrentShareEvidenceClosure,
    CurrentShareEvidenceError,
    derive_current_share_evidence_closure,
)
from .valuation_handoff_policies import (
    ASSUMPTION_CANDIDATE_POLICY_ID,
    ASSUMPTION_CANDIDATE_POLICY_VERSION,
    ASSUMPTION_EVIDENCE_POLICY_ID,
    ASSUMPTION_EVIDENCE_POLICY_VERSION,
    ASSUMPTION_SLOT_POLICY_ID,
    ASSUMPTION_SLOT_POLICY_VERSION,
    HANDOFF_POLICY_ID,
    HANDOFF_POLICY_VERSION,
    HANDOFF_STATES,
    HANDOFF_TRANSITIONS,
    MARKET_REFERENCE_POLICY_ID,
    MARKET_REFERENCE_POLICY_VERSION,
    PRICE_BLIND_FREEZE_POLICY_ID,
    PRICE_BLIND_FREEZE_POLICY_VERSION,
    RESEARCH_BUNDLE_ONLY_ROLES,
    SUPPLEMENTAL_REFERENCE_ROLES,
    TARGET_SECURITY_FORBIDDEN_CONCEPT_TOKENS,
    assumption_evidence_policy_sha256,
    assumption_slot_policy,
    assumption_slot_policy_sha256,
    empty_supplemental_reference_closure_sha256,
    legacy_handoff_v2_kernel_identity,
    method_assumption_policy,
    price_blind_freeze_policy_sha256,
)
from .valuation_share_event_integration_types import CurrentShareEvidenceClosureV2


class ValuationHandoffValidationError(ValueError):
    pass


EVIDENCE_FIELDS = {
    "Fact": "facts",
    "CalculationResult": "calculations",
    "Claim": "claims",
    "AccountingQualityReview": "accounting_quality_reviews",
    "ManagementReview": "management_reviews",
    "BusinessQualityReview": "business_quality_reviews",
    "CapitalAllocationReview": "capital_allocation_reviews",
}

_PRICE_BLIND_HANDOFF_STATES = frozenset(
    {
        "evidence_open",
        "price_blind_candidates_reviewed",
        "price_blind_input_frozen",
        "market_reference_allowed",
    }
)


def _pre_market_replay_graph(
    graph: Any,
    *,
    handoffs: tuple[ValuationHandoff, ...] | None = None,
) -> Any:
    """Return a validation view that cannot recursively re-enter market validation."""

    snapshots = tuple(graph.market_reference_snapshots)
    market_document_ids = {item.quote_source_document_id for item in snapshots}
    market_fact_ids = {item.quote_fact_id for item in snapshots}
    market_calculation_ids = {
        str(item.market_equity["calculation_id"]) for item in snapshots
    }
    replay_handoffs = (
        tuple(handoffs)
        if handoffs is not None
        else tuple(
            item
            for item in graph.valuation_handoffs
            if item.state in _PRICE_BLIND_HANDOFF_STATES
        )
    )
    return replace(
        graph,
        documents=tuple(
            item for item in graph.documents if item.document_id not in market_document_ids
        ),
        facts=tuple(item for item in graph.facts if item.fact_id not in market_fact_ids),
        calculations=tuple(
            item
            for item in graph.calculations
            if item.calculation_id not in market_calculation_ids
        ),
        market_reference_snapshots=(),
        market_reference_validation_contexts=(),
        valuation_handoffs=replay_handoffs,
    )


def _index(items: tuple[Contract, ...], attribute: str) -> dict[str, Contract]:
    return {getattr(item, attribute): item for item in items}


def _bundle_roots(bundle: Contract) -> tuple[str, ...]:
    return tuple(
        object_id for reference in bundle.module_references for object_id in reference["object_ids"]
    )


def _bundle_closure(graph: Any, bundle: Contract) -> dict[str, tuple[str, Contract]]:
    return dependency_closure(graph, _bundle_roots(bundle))


def _supplemental_closures(graph: Any) -> dict[str, Any]:
    closures: dict[str, Any] = {}
    for closure in graph.price_blind_reference_closures:
        if closure.fingerprint in closures:
            raise ValuationHandoffValidationError(
                "PriceBlindReferenceClosure fingerprint is not unique"
            )
        closures[closure.fingerprint] = closure
    return closures


def _supplemental_objects(closure: Any) -> tuple[dict[str, Contract], dict[str, Contract]]:
    return (
        {item.document_id: item for item in closure.documents},
        {item.fact_id: item for item in closure.facts},
    )


def candidate_evidence_graph_sha256(graph: Any, candidate: ValuationAssumptionCandidate) -> str:
    """Replay the candidate's typed evidence graph without generating a candidate."""

    bundles = _index(graph.research_bundles, "bundle_id")
    bundle = bundles.get(candidate.research_bundle_id)
    if bundle is None:
        raise ValuationHandoffValidationError("ValuationAssumptionCandidate lacks ResearchBundle")
    research_closure = _bundle_closure(graph, bundle)
    supplemental = _supplemental_closures(graph).get(
        candidate.supplemental_reference_closure_sha256
    )
    supplemental_documents: dict[str, Contract] = {}
    supplemental_facts: dict[str, Contract] = {}
    if supplemental is not None:
        supplemental_documents, supplemental_facts = _supplemental_objects(supplemental)

    entries = []
    for binding in sorted(candidate.evidence_bindings, key=lambda item: item["binding_id"]):
        identifier = binding["object_id"]
        domain = binding["evidence_domain"]
        source_content_sha256 = None
        if domain == "research_bundle":
            matching = research_closure.get(identifier)
            if matching is None or matching[0] != binding["contract_type"]:
                raise ValuationHandoffValidationError(
                    "ValuationAssumptionCandidate "
                    f"{candidate.candidate_id} has dangling typed evidence"
                )
            item = matching[1]
        else:
            if binding["contract_type"] != "Fact":
                raise ValuationHandoffValidationError(
                    "supplemental price-blind evidence must be a Fact"
                )
            item = supplemental_facts.get(identifier)
            if item is None:
                raise ValuationHandoffValidationError(
                    "ValuationAssumptionCandidate has dangling supplemental evidence"
                )
            source = supplemental_documents[item.source_document_id]
            source_content_sha256 = source.content_sha256
        entries.append(
            {
                "binding_id": binding["binding_id"],
                "role": binding["role"],
                "slot_evidence_role": binding["slot_evidence_role"],
                "evidence_domain": domain,
                "contract_type": binding["contract_type"],
                "object_id": identifier,
                "object_fingerprint": item.fingerprint,
                "source_content_sha256": source_content_sha256,
            }
        )
    return canonical_sha256(
        {
            "research_bundle_dependency_sha256": bundle.dependency_closure_sha256,
            "supplemental_reference_closure_sha256": (
                candidate.supplemental_reference_closure_sha256
            ),
            "entries": entries,
        }
    )


def _object_id(item: Contract) -> str:
    for attribute in (
        "fact_id",
        "calculation_id",
        "claim_id",
        "review_id",
        "candidate_id",
        "decision_id",
        "snapshot_id",
        "handoff_id",
    ):
        value = getattr(item, attribute, None)
        if isinstance(value, str):
            return value
    raise ValuationHandoffValidationError(f"{type(item).__name__} has no registered identifier")


def _reject_cycles(edges: dict[str, tuple[str, ...]], label: str) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise ValuationHandoffValidationError(f"{label} contains a cycle")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in edges.get(identifier, ()):
            if dependency not in edges:
                raise ValuationHandoffValidationError(
                    f"{label} has dangling predecessor: {dependency}"
                )
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in edges:
        visit(identifier)


def _validate_candidate(
    graph: Any,
    candidate: ValuationAssumptionCandidate,
    bundles: dict[str, Contract],
) -> None:
    if (
        candidate.candidate_policy_id != ASSUMPTION_CANDIDATE_POLICY_ID
        or candidate.candidate_policy_version != ASSUMPTION_CANDIDATE_POLICY_VERSION
    ):
        raise ValuationHandoffValidationError("ValuationAssumptionCandidate policy mismatch")
    bundle = bundles.get(candidate.research_bundle_id)
    if bundle is None:
        raise ValuationHandoffValidationError("ValuationAssumptionCandidate lacks ResearchBundle")
    if (
        candidate.issuer_id != bundle.issuer_id
        or candidate.data_cutoff_date != bundle.data_cutoff_date
        or candidate.research_bundle_fingerprint != bundle.bundle_fingerprint
        or candidate.research_bundle_dependency_sha256 != bundle.dependency_closure_sha256
    ):
        raise ValuationHandoffValidationError(
            "ValuationAssumptionCandidate ResearchBundle identity mismatch"
        )

    method_policy = method_assumption_policy(candidate.method_scope)
    if candidate.kernel_concept not in method_policy.concepts:
        raise ValuationHandoffValidationError("Candidate concept is outside its method policy")
    if method_policy.scenario_required:
        if candidate.scenario not in method_policy.scenarios:
            raise ValuationHandoffValidationError("McKinsey candidate scenario mismatch")
    elif candidate.scenario is not None:
        raise ValuationHandoffValidationError("Penman candidate scenario must be null")

    try:
        slot = assumption_slot_policy(candidate.assumption_slot_id)
    except KeyError as exc:
        raise ValuationHandoffValidationError(str(exc)) from exc
    if (
        slot.method_scope != candidate.method_scope
        or slot.kernel_concept != candidate.kernel_concept
        or slot.horizon_kind != candidate.horizon["kind"]
    ):
        raise ValuationHandoffValidationError(
            "Candidate slot, method, concept, or horizon policy mismatch"
        )
    if candidate.method_scope == "mckinsey" and candidate.assumption_slot_id.split(".")[1] != (
        candidate.scenario
    ):
        raise ValuationHandoffValidationError("Candidate slot scenario mismatch")
    actual_unit_family = unit_spec(candidate.unit).family
    if slot.unit_family == "rate":
        unit_ok = actual_unit_family.startswith("rate:")
    else:
        unit_ok = actual_unit_family == slot.unit_family
    if not unit_ok:
        raise ValuationHandoffValidationError("Candidate slot unit family mismatch")

    horizon_start = candidate.horizon["start_date"]
    horizon_end = candidate.horizon["end_date"]
    if horizon_start is not None and date.fromisoformat(horizon_start) > date.fromisoformat(
        horizon_end
    ):
        raise ValuationHandoffValidationError("Candidate horizon starts after it ends")
    binding_ids = [item["binding_id"] for item in candidate.evidence_bindings]
    if len(binding_ids) != len(set(binding_ids)):
        raise ValuationHandoffValidationError("Candidate has duplicate evidence binding IDs")

    closure = _bundle_closure(graph, bundle)
    supplemental_closures = _supplemental_closures(graph)
    supplemental = supplemental_closures.get(candidate.supplemental_reference_closure_sha256)
    supplemental_bindings = [
        item
        for item in candidate.evidence_bindings
        if item["evidence_domain"] == "supplemental_price_blind"
    ]
    if supplemental_bindings and supplemental is None:
        raise ValuationHandoffValidationError(
            "Candidate supplemental reference closure is unavailable"
        )
    if not supplemental_bindings and (
        candidate.supplemental_reference_closure_sha256
        != empty_supplemental_reference_closure_sha256()
    ):
        raise ValuationHandoffValidationError(
            "Candidate without supplemental evidence must use the canonical empty closure"
        )
    if supplemental is not None and (
        supplemental.target_issuer_id != candidate.issuer_id
        or supplemental.data_cutoff_date != candidate.data_cutoff_date
    ):
        raise ValuationHandoffValidationError(
            "Candidate supplemental closure issuer or cutoff mismatch"
        )
    supplemental_documents: dict[str, Contract] = {}
    supplemental_facts: dict[str, Contract] = {}
    if supplemental is not None:
        supplemental_documents, supplemental_facts = _supplemental_objects(supplemental)

    typed_support = False
    support_roles: set[str] = set()
    for binding in candidate.evidence_bindings:
        object_id = binding["object_id"]
        slot_role = binding["slot_evidence_role"]
        if slot_role not in slot.allowed_evidence_roles:
            raise ValuationHandoffValidationError("Candidate evidence role is invalid for its slot")
        if binding["role"] == "support":
            support_roles.add(slot_role)
        if binding["evidence_domain"] == "research_bundle":
            if slot_role not in RESEARCH_BUNDLE_ONLY_ROLES:
                raise ValuationHandoffValidationError(
                    "supplemental evidence role cannot be sourced from ResearchBundle"
                )
            if object_id not in closure:
                raise ValuationHandoffValidationError(
                    "Candidate evidence is outside the ResearchBundle dependency closure"
                )
            actual_type, item = closure[object_id]
            if actual_type != binding["contract_type"]:
                raise ValuationHandoffValidationError("Candidate evidence type mismatch")
            if actual_type in {"Fact", "CalculationResult"} and binding["role"] == "support":
                typed_support = True
            if getattr(item, "issuer_id", candidate.issuer_id) != candidate.issuer_id:
                raise ValuationHandoffValidationError("Candidate research evidence crosses issuers")
            continue

        role_policy = SUPPLEMENTAL_REFERENCE_ROLES.get(slot_role)
        if role_policy is None or binding["contract_type"] != "Fact":
            raise ValuationHandoffValidationError(
                "Candidate supplemental evidence role or type is not registered"
            )
        fact = supplemental_facts.get(object_id)
        if fact is None:
            raise ValuationHandoffValidationError("Candidate supplemental Fact is unavailable")
        document = supplemental_documents[fact.source_document_id]
        if document.authority_level not in role_policy.authority_levels:
            raise ValuationHandoffValidationError(
                "Candidate supplemental source authority is not eligible for its role"
            )
        if role_policy.requires_commit_pinned_url and not any(
            len(part) == 40 and all(character in "0123456789abcdef" for character in part)
            for part in document.source_url.split("/")
        ):
            raise ValuationHandoffValidationError("owner hurdle policy source is not commit-pinned")
        lowered = fact.concept.lower()
        if any(token in lowered for token in TARGET_SECURITY_FORBIDDEN_CONCEPT_TOKENS):
            raise ValuationHandoffValidationError(
                "target-security market evidence cannot enter the price-blind closure"
            )
        if binding["role"] == "support":
            typed_support = True
    if not typed_support:
        raise ValuationHandoffValidationError(
            "Candidate requires price-blind Fact or CalculationResult support"
        )
    if not slot.required_support_roles.issubset(support_roles):
        raise ValuationHandoffValidationError(
            "Candidate lacks required support roles for its assumption slot"
        )
    if candidate.evidence_graph_sha256 != candidate_evidence_graph_sha256(graph, candidate):
        raise ValuationHandoffValidationError("Candidate evidence graph hash mismatch")

    market_document_ids = {
        item.document_id for item in graph.documents if item.authority_level == "market_reference"
    }
    for _, item in closure.values():
        source_id = getattr(item, "source_document_id", None)
        if source_id in market_document_ids:
            raise ValuationHandoffValidationError(
                "ResearchBundle evidence cannot depend on market evidence"
            )
    if candidate.validation_status == "eligible" and candidate.validation_issues:
        raise ValuationHandoffValidationError("Eligible Candidate cannot retain validation issues")


def _validate_decisions(graph: Any, candidates: dict[str, Contract]) -> None:
    decisions = _index(graph.valuation_assumption_review_decisions, "decision_id")
    _reject_cycles(
        {
            item.decision_id: (
                (item.supersedes_decision_id,) if item.supersedes_decision_id is not None else ()
            )
            for item in graph.valuation_assumption_review_decisions
        },
        "ValuationAssumptionReviewDecision",
    )
    reserved: dict[str, str] = {}
    confirmed_by_candidate: defaultdict[str, list[str]] = defaultdict(list)
    confirmed_by_slot: defaultdict[str, list[str]] = defaultdict(list)
    superseded_targets = {
        item.supersedes_decision_id
        for item in graph.valuation_assumption_review_decisions
        if item.supersedes_decision_id is not None
    }
    for decision in graph.valuation_assumption_review_decisions:
        candidate = candidates.get(decision.candidate_id)
        if candidate is None:
            raise ValuationHandoffValidationError("Decision has dangling Candidate")
        if (
            decision.issuer_id != candidate.issuer_id
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
        ):
            raise ValuationHandoffValidationError("Decision does not bind the exact Candidate")
        if decision.decision == "confirmed":
            if candidate.validation_status != "eligible":
                raise ValuationHandoffValidationError("Blocked Candidate cannot be confirmed")
            assumption_id = decision.reserved_kernel_assumption_id
            assert assumption_id is not None
            previous = reserved.setdefault(assumption_id, decision.decision_id)
            if previous != decision.decision_id:
                raise ValuationHandoffValidationError("Reserved kernel assumption ID is not unique")
            if decision.decision_id not in superseded_targets:
                confirmed_by_candidate[decision.candidate_id].append(decision.decision_id)
                confirmed_by_slot[candidate.assumption_slot_id].append(decision.decision_id)
        if decision.decision == "superseded":
            previous = decisions[decision.supersedes_decision_id]
            if previous.candidate_id != decision.candidate_id or previous.decision != "confirmed":
                raise ValuationHandoffValidationError(
                    "Decision supersession must retire a confirmed Decision for the same Candidate"
                )
            if datetime.fromisoformat(
                decision.reviewed_at.replace("Z", "+00:00")
            ) <= datetime.fromisoformat(previous.reviewed_at.replace("Z", "+00:00")):
                raise ValuationHandoffValidationError("Decision supersession is not chronological")
    if any(len(items) > 1 for items in confirmed_by_candidate.values()):
        raise ValuationHandoffValidationError("Candidate has multiple active confirmed Decisions")
    if any(len(items) > 1 for items in confirmed_by_slot.values()):
        raise ValuationHandoffValidationError(
            "Assumption slot has multiple active confirmed Decisions"
        )


def _validate_handoffs(
    graph: Any,
    bundles: dict[str, Contract],
    candidates: dict[str, Contract],
    decisions: dict[str, Contract],
    snapshots: dict[str, Contract],
) -> None:
    handoffs = _index(graph.valuation_handoffs, "handoff_id")
    _reject_cycles(
        {
            item.handoff_id: tuple(
                reference
                for reference in (item.predecessor_handoff_id, item.supersedes_handoff_id)
                if reference is not None
            )
            for item in graph.valuation_handoffs
        },
        "ValuationHandoff",
    )
    expected_kernel = legacy_handoff_v2_kernel_identity()
    expected_lock_sha = file_sha256(graph.component_lock_path)
    manifests = _index(graph.manifests, "run_id")
    supplemental_closures = _supplemental_closures(graph)
    allowed_supplemental_hashes = {
        empty_supplemental_reference_closure_sha256(),
        *supplemental_closures,
    }
    by_run: defaultdict[str, list[ValuationHandoff]] = defaultdict(list)

    for handoff in graph.valuation_handoffs:
        if (
            handoff.handoff_policy_id != HANDOFF_POLICY_ID
            or handoff.handoff_policy_version != HANDOFF_POLICY_VERSION
        ):
            raise ValuationHandoffValidationError("ValuationHandoff policy mismatch")
        if (
            handoff.assumption_slot_policy_id != ASSUMPTION_SLOT_POLICY_ID
            or handoff.assumption_slot_policy_version != ASSUMPTION_SLOT_POLICY_VERSION
            or handoff.assumption_slot_policy_sha256 != assumption_slot_policy_sha256()
            or handoff.assumption_evidence_policy_id != ASSUMPTION_EVIDENCE_POLICY_ID
            or handoff.assumption_evidence_policy_version != ASSUMPTION_EVIDENCE_POLICY_VERSION
            or handoff.assumption_evidence_policy_sha256 != assumption_evidence_policy_sha256()
            or handoff.price_blind_freeze_policy_id != PRICE_BLIND_FREEZE_POLICY_ID
            or handoff.price_blind_freeze_policy_version != PRICE_BLIND_FREEZE_POLICY_VERSION
            or handoff.price_blind_freeze_policy_sha256 != price_blind_freeze_policy_sha256()
        ):
            raise ValuationHandoffValidationError("ValuationHandoff policy hash mismatch")
        if handoff.supplemental_reference_closure_sha256 not in allowed_supplemental_hashes:
            raise ValuationHandoffValidationError(
                "ValuationHandoff supplemental reference closure is unavailable"
            )
        bundle = bundles.get(handoff.research_bundle_id)
        manifest = manifests.get(handoff.research_run_manifest_id)
        if bundle is None or manifest is None:
            raise ValuationHandoffValidationError("ValuationHandoff lacks Bundle or RunManifest")
        if (
            handoff.issuer_id != bundle.issuer_id
            or handoff.data_cutoff_date != bundle.data_cutoff_date
            or handoff.research_bundle_fingerprint != bundle.bundle_fingerprint
            or handoff.research_bundle_dependency_sha256 != bundle.dependency_closure_sha256
            or handoff.research_run_manifest_id != bundle.run_id
            or manifest.issuer_id != handoff.issuer_id
            or manifest.data_cutoff_date != handoff.data_cutoff_date
        ):
            raise ValuationHandoffValidationError("ValuationHandoff research identity mismatch")
        if (
            handoff.component_lock_sha256 != expected_lock_sha
            or dict(handoff.kernel_identity) != expected_kernel
        ):
            raise ValuationHandoffValidationError(
                "ValuationHandoff component or kernel lock mismatch"
            )
        if len(handoff.assumption_candidate_ids) != len(set(handoff.assumption_candidate_ids)):
            raise ValuationHandoffValidationError("ValuationHandoff repeats Candidate IDs")
        if len(handoff.assumption_review_decision_ids) != len(
            set(handoff.assumption_review_decision_ids)
        ):
            raise ValuationHandoffValidationError("ValuationHandoff repeats Decision IDs")
        for candidate_id in handoff.assumption_candidate_ids:
            candidate = candidates.get(candidate_id)
            if (
                candidate is None
                or candidate.research_bundle_id != bundle.bundle_id
                or candidate.supplemental_reference_closure_sha256
                != handoff.supplemental_reference_closure_sha256
            ):
                raise ValuationHandoffValidationError("ValuationHandoff Candidate mismatch")
        decision_candidate_ids: set[str] = set()
        for decision_id in handoff.assumption_review_decision_ids:
            decision = decisions.get(decision_id)
            if decision is None:
                raise ValuationHandoffValidationError("ValuationHandoff Decision is dangling")
            decision_candidate_ids.add(decision.candidate_id)
        if decision_candidate_ids - set(handoff.assumption_candidate_ids):
            raise ValuationHandoffValidationError("ValuationHandoff Decision set is inconsistent")
        if handoff.state != "evidence_open" and decision_candidate_ids != set(
            handoff.assumption_candidate_ids
        ):
            raise ValuationHandoffValidationError("Reviewed Handoff lacks Candidate Decisions")
        if handoff.market_reference_snapshot_id is not None:
            snapshot = snapshots.get(handoff.market_reference_snapshot_id)
            if snapshot is None or snapshot.issuer_id != handoff.issuer_id:
                raise ValuationHandoffValidationError("ValuationHandoff MarketReference mismatch")
        by_run[handoff.handoff_run_id].append(handoff)

    for run_id, versions in by_run.items():
        ordered = sorted(versions, key=lambda item: item.handoff_version)
        if [item.handoff_version for item in ordered] != list(range(1, len(ordered) + 1)):
            raise ValuationHandoffValidationError(
                f"Handoff run {run_id} versions are not contiguous"
            )
        if ordered[0].state != HANDOFF_STATES[0] or ordered[0].predecessor_handoff_id is not None:
            raise ValuationHandoffValidationError("Handoff run must start at evidence_open")
        frozen_candidates: tuple[str, ...] | None = None
        frozen_decisions: tuple[str, ...] | None = None
        protected: tuple[str, str, str] | None = None
        root = ordered[0]
        for position, handoff in enumerate(ordered):
            if position:
                previous = ordered[position - 1]
                if (
                    handoff.predecessor_handoff_id != previous.handoff_id
                    or HANDOFF_TRANSITIONS.get(previous.state) != handoff.state
                ):
                    raise ValuationHandoffValidationError("Handoff transition is not adjacent")
                if datetime.fromisoformat(
                    handoff.transitioned_at.replace("Z", "+00:00")
                ) <= datetime.fromisoformat(previous.transitioned_at.replace("Z", "+00:00")):
                    raise ValuationHandoffValidationError(
                        "Handoff transition timestamp is not chronological"
                    )
                immutable = (
                    "issuer_id",
                    "data_cutoff_date",
                    "research_bundle_id",
                    "research_bundle_fingerprint",
                    "research_bundle_dependency_sha256",
                    "research_run_manifest_id",
                    "supplemental_reference_closure_sha256",
                    "mapping_policy_id",
                    "mapping_policy_version",
                    "assumption_slot_policy_id",
                    "assumption_slot_policy_version",
                    "assumption_slot_policy_sha256",
                    "assumption_evidence_policy_id",
                    "assumption_evidence_policy_version",
                    "assumption_evidence_policy_sha256",
                    "price_blind_freeze_policy_id",
                    "price_blind_freeze_policy_version",
                    "price_blind_freeze_policy_sha256",
                    "component_lock_sha256",
                    "kernel_identity",
                )
                if any(getattr(handoff, name) != getattr(root, name) for name in immutable):
                    raise ValuationHandoffValidationError(
                        "Handoff immutable research input drifted"
                    )
            if handoff.state == "price_blind_candidates_reviewed":
                frozen_candidates = tuple(sorted(handoff.assumption_candidate_ids))
                frozen_decisions = tuple(sorted(handoff.assumption_review_decision_ids))
            if frozen_candidates is not None and (
                tuple(sorted(handoff.assumption_candidate_ids)) != frozen_candidates
                or tuple(sorted(handoff.assumption_review_decision_ids)) != frozen_decisions
            ):
                raise ValuationHandoffValidationError("Handoff Candidate or Decision set changed")
            if handoff.state == "price_blind_input_frozen":
                protected = (
                    handoff.price_blind_input_fingerprint,
                    handoff.protected_mckinsey_sha256,
                    handoff.protected_penman_assumptions_sha256,
                )
            if (
                protected is not None
                and (
                    handoff.price_blind_input_fingerprint,
                    handoff.protected_mckinsey_sha256,
                    handoff.protected_penman_assumptions_sha256,
                )
                != protected
            ):
                raise ValuationHandoffValidationError(
                    "Handoff protected price-blind hashes changed"
                )

        if root.supersedes_handoff_id is None:
            if root.quarantined_market_reference_snapshot_ids:
                raise ValuationHandoffValidationError(
                    "Initial Handoff run cannot quarantine markets"
                )
        else:
            prior = handoffs[root.supersedes_handoff_id]
            if (
                prior.handoff_run_id == root.handoff_run_id
                or root.predecessor_handoff_id is not None
            ):
                raise ValuationHandoffValidationError("Replacement Handoff root is invalid")
            prior_run_snapshots = {
                item.market_reference_snapshot_id
                for item in by_run[prior.handoff_run_id]
                if item.market_reference_snapshot_id is not None
            }
            if not prior_run_snapshots.issubset(
                set(root.quarantined_market_reference_snapshot_ids)
            ):
                raise ValuationHandoffValidationError(
                    "Replacement Handoff did not quarantine prior market evidence"
                )


def parser_replay_fingerprint(snapshot_payload: dict[str, Any], receipt: Any) -> str:
    """Hash the exact raw/parser/request/parsed-quote replay surface."""

    raw = snapshot_payload["raw_evidence"]
    authority = snapshot_payload["authority_lineage"]
    return canonical_sha256(
        {
            "raw_response_sha256": raw["raw_response_sha256"],
            "content_type": raw["content_type"],
            "provider_registration_sha256": authority["provider_registration_sha256"],
            "parser_sha256": authority["parser_sha256"],
            "request_fingerprint": snapshot_payload["market_quote_request"]["request_fingerprint"],
            "parsed_quote": {
                "security_id": receipt.security_id,
                "ticker": receipt.ticker,
                "exchange": receipt.exchange,
                "share_class": receipt.share_class,
                "trading_date": receipt.trading_date,
                "quote_timestamp": receipt.quote_timestamp,
                "session_kind": receipt.session_kind,
                "session_status": receipt.session_status,
                "instrument_status": receipt.instrument_status,
                "price_basis": receipt.price_basis,
                "quote_price": receipt.quote_price,
                "quote_currency": receipt.quote_currency,
            },
        }
    )


def claim_control_fingerprint(
    *,
    price_blind_input_fingerprint: str,
    share_basis_decision_fingerprint: str,
    claim_control_authority_fingerprint: str,
    current_share_numeric_root_fact_ids: tuple[str, ...],
    excluded_claim_root_fact_ids: tuple[str, ...],
) -> str:
    return canonical_sha256(
        {
            "price_blind_input_fingerprint": price_blind_input_fingerprint,
            "share_basis_decision_fingerprint": share_basis_decision_fingerprint,
            "claim_control_authority_fingerprint": claim_control_authority_fingerprint,
            "current_share_numeric_root_fact_ids": tuple(
                sorted(current_share_numeric_root_fact_ids)
            ),
            "included_claim_root_fact_ids": (),
            "excluded_claim_root_fact_ids": tuple(sorted(excluded_claim_root_fact_ids)),
            "blocked_claim_root_fact_ids": (),
            "overlap_fact_ids": (),
        }
    )


def future_request_v2_mapping_fingerprint(
    *,
    price_blind_input_fingerprint: str,
    shares_outstanding_fact_id: str,
    evidence_kind: str,
) -> str:
    """Seal the future rc.2 request mapping without constructing a request."""

    return canonical_sha256(
        {
            "price_blind_input_fingerprint": price_blind_input_fingerprint,
            "share_denominator_fact_id": shares_outstanding_fact_id,
            "share_denominator_kind": "current_common_shares_outstanding",
            "share_denominator_evidence_kind": evidence_kind,
        }
    )


def _contract_object(graph: Any, contract_type: str, object_id: str) -> Contract | None:
    field_and_id = {
        "SourceDocument": ("documents", "document_id"),
        "Fact": ("facts", "fact_id"),
        "Claim": ("claims", "claim_id"),
    }
    field, attribute = field_and_id[contract_type]
    return next(
        (item for item in getattr(graph, field) if getattr(item, attribute) == object_id),
        None,
    )


def market_evidence_closure_sha256(
    graph: Any,
    snapshot_payload: dict[str, Any],
    authorization: Contract,
    context: Any,
) -> str:
    """Replay the typed market-evidence closure without constructing a Snapshot."""

    access = context.market_access_result
    request = access.request
    governed = access.receipt
    security = context.security_compilation_result
    share_compilation = context.current_share_compilation_result
    share_basis = share_compilation.share_basis_decision
    claim_control_authority = context.claim_control_authority
    assert (
        request is not None
        and governed is not None
        and security.evidence_closure is not None
        and share_basis is not None
    )
    receipt = governed.receipt
    documents = _index(graph.documents, "document_id")
    facts = _index(graph.facts, "fact_id")
    calculations = _index(graph.calculations, "calculation_id")
    share = snapshot_payload["share_basis"]
    market_equity = snapshot_payload["market_equity"]
    current_share_fact = facts.get(share["shares_outstanding_fact_id"])
    if current_share_fact is None:
        raise ValuationHandoffValidationError("Market-evidence closure lacks current shares")
    share_evidence = _validate_current_share_lineage(
        graph=graph,
        share_fact=current_share_fact,
        evidence_kind=share_basis.evidence_kind,
        trading_date=snapshot_payload["trading_date"],
        data_cutoff_date=snapshot_payload["data_cutoff_date"],
        security_compilation_result=security,
        share_basis_decision=share_basis,
        claim_control_authority=claim_control_authority,
        expected_closure=share_compilation.evidence_closure,
    )
    if share_evidence.closure_sha256 != share_compilation.evidence_closure.closure_sha256:
        raise ValuationHandoffValidationError(
            "MarketReferenceSnapshot current-share compilation does not replay"
        )
    entries: set[tuple[str, str, str]] = {
        ("ValuationHandoff", authorization.handoff_id, authorization.fingerprint),
        (
            "PriceBlindInputArtifact",
            context.price_blind_artifact.fingerprint,
            context.price_blind_artifact.fingerprint,
        ),
        ("MarketAccessResult", access.fingerprint, access.fingerprint),
        ("MarketQuoteRequest", request.request_id, request.request_fingerprint),
        ("GovernedMarketQuoteReceipt", receipt.receipt_id, governed.fingerprint),
        (
            "SecurityIdentityCompilationResult",
            security.proposal.proposal_id,
            security.fingerprint,
        ),
        (
            "SecurityIdentityEvidenceClosure",
            security.evidence_closure.review_decision_id,
            security.evidence_closure.closure_sha256,
        ),
        ("ShareBasisDecision", share_basis.decision_id, share_basis.fingerprint),
        (
            "CurrentShareCompilationResult",
            share_compilation.fingerprint,
            share_compilation.fingerprint,
        ),
        (
            "Phase5CDilutionClaimAuthority",
            claim_control_authority.equity_bridge_fingerprint,
            claim_control_authority.fingerprint,
        ),
        (
            "CurrentShareEvidenceClosure",
            share_evidence.closure_id,
            share_evidence.closure_sha256,
        ),
        (
            "RawMarketResponse",
            governed.raw_response_sha256,
            governed.raw_response_sha256,
        ),
    }
    if governed.evidence_mode == "human_reviewed_file":
        if (
            context.authorization_reservation is None
            or context.authorization_consumption is None
        ):
            raise ValuationHandoffValidationError(
                "Reviewed market closure lacks authorization attestations"
            )
        entries.add(
            (
                "MarketAuthorizationReservation",
                context.authorization_reservation.reservation_id,
                context.authorization_reservation.fingerprint,
            )
        )
        entries.add(
            (
                "MarketAuthorizationConsumption",
                context.authorization_consumption.consumption_id,
                context.authorization_consumption.fingerprint,
            )
        )
    elif (
        context.authorization_reservation is not None
        or context.authorization_consumption is not None
    ):
        raise ValuationHandoffValidationError(
            "Fixture market closure cannot inject authorization attestations"
        )
    entries.update(share_evidence.object_fingerprints)
    referenced = (
        ("SourceDocument", snapshot_payload["quote_source_document_id"], documents),
        ("Fact", snapshot_payload["quote_fact_id"], facts),
        ("Fact", share["shares_outstanding_fact_id"], facts),
        ("CalculationResult", market_equity["calculation_id"], calculations),
    )
    for contract_type, object_id, domain in referenced:
        item = domain.get(object_id)
        if item is None:
            raise ValuationHandoffValidationError("Market-evidence closure has dangling evidence")
        entries.add((contract_type, object_id, item.fingerprint))
    for binding in share["corporate_action_evidence_bindings"]:
        item = _contract_object(graph, binding["contract_type"], binding["object_id"])
        if item is None:
            raise ValuationHandoffValidationError("Corporate-action evidence is dangling")
        entries.add((binding["contract_type"], binding["object_id"], item.fingerprint))
    return canonical_sha256(
        {
            "issuer_id": snapshot_payload["issuer_id"],
            "data_cutoff_date": snapshot_payload["data_cutoff_date"],
            "raw_evidence_locator": snapshot_payload["raw_evidence"]["locator"],
            "entries": tuple(
                {
                    "contract_type": contract_type,
                    "object_id": object_id,
                    "fingerprint": fingerprint,
                }
                for contract_type, object_id, fingerprint in sorted(entries)
            ),
        }
    )


def _validate_current_share_lineage(
    *,
    graph: Any,
    share_fact: Contract,
    evidence_kind: str,
    trading_date: str,
    data_cutoff_date: str,
    security_compilation_result: Any,
    share_basis_decision: Any,
    claim_control_authority: Any,
    expected_closure: CurrentShareEvidenceClosure | CurrentShareEvidenceClosureV2 | None = None,
) -> CurrentShareEvidenceClosure | CurrentShareEvidenceClosureV2:
    """Derive a recursive, cutoff-safe share authority from the exact ContractGraph."""

    if isinstance(expected_closure, CurrentShareEvidenceClosureV2):
        from .valuation_current_share_compiler import (
            derive_current_share_evidence_closure_v2,
        )

        derived_ids = {
            expected_closure.output_share_fact_id,
            *(
                item.canonical_event_fact_id
                for item in expected_closure.materializations
            ),
        }
        pre_market_graph = _pre_market_replay_graph(graph)
        replay_graph = replace(
            pre_market_graph,
            facts=tuple(
                item
                for item in pre_market_graph.facts
                if item.fact_id not in derived_ids
            ),
            calculations=tuple(
                item
                for item in pre_market_graph.calculations
                if not set(item.input_fact_ids).intersection(derived_ids)
            ),
        )
        try:
            replayed = derive_current_share_evidence_closure_v2(
                graph=replay_graph,
                grouping_result=expected_closure.grouping_result,
                opening_share_fact=expected_closure.opening_share_fact,
                security_compilation_result=security_compilation_result,
                claim_control_authority=(
                    expected_closure.claim_transition_reconciliation.claim_control_authority
                ),
                quote_date=trading_date,
                data_cutoff_date=data_cutoff_date,
                expected_research_bundle_id=(
                    expected_closure.bundle_evidence_closure.research_bundle_id
                ),
            )
        except ValueError as exc:
            raise ValuationHandoffValidationError(str(exc)) from exc
        if (
            replayed != expected_closure
            or replayed.output_share_fact != share_fact
            or share_basis_decision.share_fact_id != share_fact.fact_id
        ):
            raise ValuationHandoffValidationError(
                "Current-share V2 evidence closure does not replay"
            )
        return replayed
    try:
        return derive_current_share_evidence_closure(
            graph=graph,
            share_fact=share_fact,
            evidence_kind=evidence_kind,
            trading_date=trading_date,
            data_cutoff_date=data_cutoff_date,
            security_compilation_result=security_compilation_result,
            share_basis_decision=share_basis_decision,
            claim_control_authority=claim_control_authority,
        )
    except CurrentShareEvidenceError as exc:
        raise ValuationHandoffValidationError(str(exc)) from exc


def _validate_raw_evidence(graph: Any, snapshot: MarketReferenceSnapshot, context: Any) -> None:
    from .valuation_market_authority import load_market_access_authority
    from .valuation_market_runtime import contains_secret_material

    raw = snapshot.raw_evidence
    raw_bytes: bytes | None = None
    if raw["locator"] != context.raw_evidence_locator or contains_secret_material(raw):
        raise ValuationHandoffValidationError("Raw evidence locator is unsafe or mismatched")
    locator = raw["locator"]
    if raw["store_kind"] == "repository_fixture":
        if not locator.startswith("repo://"):
            raise ValuationHandoffValidationError("Repository raw evidence locator is invalid")
        relative = locator.removeprefix("repo://")
        parts = PurePosixPath(relative).parts
        if (
            not relative.startswith("tests/fixtures/")
            or ".." in parts
            or "?" in relative
            or "#" in relative
            or "@" in relative
        ):
            raise ValuationHandoffValidationError("Repository raw evidence locator is unsafe")
        root = graph.component_lock_path.resolve().parent
        path = (root / relative).resolve()
        if root not in path.parents or not path.is_file():
            raise ValuationHandoffValidationError("Repository raw evidence is unavailable")
        raw_bytes = path.read_bytes()
        if hashlib.sha256(raw_bytes).hexdigest() != raw["raw_response_sha256"]:
            raise ValuationHandoffValidationError("Repository raw evidence SHA mismatch")
    elif raw["store_kind"] == "reviewed_file":
        from .valuation_market_provider import (
            _MAX_RAW_EVIDENCE_BYTES,
            _read_regular_file,
            reviewed_file_authority_hashes,
        )

        expected = f"reviewed://sha256/{raw['raw_response_sha256']}"
        path = context.raw_evidence_path
        if locator != expected or path is None:
            raise ValuationHandoffValidationError("Reviewed-file raw evidence is unavailable")
        try:
            raw_bytes = _read_regular_file(
                path,
                label="raw market evidence",
                maximum_bytes=_MAX_RAW_EVIDENCE_BYTES,
            )
        except ValueError as exc:
            raise ValuationHandoffValidationError(str(exc)) from exc
        if hashlib.sha256(raw_bytes).hexdigest() != raw["raw_response_sha256"]:
            raise ValuationHandoffValidationError("Reviewed-file raw evidence SHA mismatch")
    else:
        expected = f"cas://sha256/{raw['raw_response_sha256']}"
        if locator != expected:
            raise ValuationHandoffValidationError("CAS raw evidence identity mismatch")
        raise ValuationHandoffValidationError(
            "Content-addressed market evidence has no active replay authority"
        )
    governed = context.market_access_result.receipt
    assert governed is not None
    receipt = governed.receipt
    expected_snapshot_id = (
        f"market-reference:{snapshot.issuer_id}:{snapshot.trading_date}:"
        f"{raw['raw_response_sha256'][:20]}"
    )
    if snapshot.snapshot_id != expected_snapshot_id:
        raise ValuationHandoffValidationError(
            "Market-reference Snapshot identity does not replay"
        )
    if snapshot.evidence_mode == "human_reviewed_file":
        expected_hashes = reviewed_file_authority_hashes(
            graph.component_lock_path,
            calendar_dataset_sha256=governed.calendar_dataset_sha256,
        )
        if (
            receipt.provider_id != "provider:human-reviewed-file"
            or governed.evidence_mode != "human_reviewed_file"
            or raw["store_kind"] != "reviewed_file"
            or any(
                getattr(governed, name) != value
                for name, value in expected_hashes.items()
            )
        ):
            raise ValuationHandoffValidationError(
                "Reviewed-file evidence does not match its provider authority"
            )
        from .valuation_market_calendar import select_latest_completed_session
        from .valuation_market_provider import (
            ReviewedFileMarketProvider,
            _timestamp,
            _verify_authorization_consumption,
        )
        from .valuation_price_blind_freeze import load_price_blind_input_artifact
        from .valuation_security_identity import compile_security_identity

        if (
            context.review_file_path is None
            or context.raw_evidence_path is None
            or context.price_blind_artifact_directory is None
            or context.price_blind_freeze_result is None
            or context.market_reference_request is None
            or context.reviewed_quote is None
            or context.authorization_reservation is None
            or context.authorization_consumption is None
        ):
            raise ValuationHandoffValidationError(
                "Reviewed-file evidence lacks its replay context"
            )
        try:
            _verify_authorization_consumption(
                graph.component_lock_path,
                context.authorization_reservation,
                context.authorization_consumption,
            )
            replayed_quote = ReviewedFileMarketProvider(
                context.review_file_path,
                context.raw_evidence_path,
            ).acquire(context.market_reference_request)
            replay_graph = _pre_market_replay_graph(
                graph,
                handoffs=context.price_blind_freeze_result.handoffs,
            )
            loaded = load_price_blind_input_artifact(
                context.price_blind_artifact_directory,
                graph=replay_graph,
                expected_result=context.price_blind_freeze_result,
            )
            replayed_security = compile_security_identity(
                graph=replay_graph,
                expected_freeze=loaded,
                proposal=context.security_compilation_result.proposal,
            )
            authority = load_market_access_authority(graph.component_lock_path)
            selection = select_latest_completed_session(
                authority,
                mic=replayed_security.decision.exchange,
                cutoff_date=date.fromisoformat(snapshot.data_cutoff_date),
                observed_at=_timestamp(
                    context.market_reference_request.request_started_at,
                    "request start",
                ),
            )
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise ValuationHandoffValidationError(
                "Reviewed-file authority replay failed"
            ) from exc
        authorization = loaded.handoffs[-1]
        expected_selection_fingerprint = canonical_sha256(
            {
                "calendar_id": selection.calendar_id,
                "trading_date": replayed_quote.trading_date,
                "dataset_sha256": selection.dataset_sha256,
                "review_receipt_sha256": replayed_quote.review_receipt_sha256,
            }
        )
        source_retrieved = _timestamp(
            replayed_quote.source_retrieved_at,
            "source retrieval time",
        )
        reviewed_at = _timestamp(replayed_quote.reviewed_at, "review time")
        request_started = _timestamp(
            context.market_reference_request.request_started_at,
            "request start",
        )
        retrieved_at = _timestamp(receipt.retrieved_at, "retrieval time")
        if (
            replayed_quote != context.reviewed_quote
            or raw["content_type"] != replayed_quote.raw_content_type
            or loaded.artifact != context.price_blind_artifact
            or replayed_security != context.security_compilation_result
            or authorization.handoff_id != snapshot.authorization_handoff_id
            or authorization.fingerprint != snapshot.authorization_handoff_fingerprint
            or selection.dataset_sha256 != governed.calendar_dataset_sha256
            or selection.calendar_id != receipt.trading_calendar_id
            or selection.session.trading_date != snapshot.trading_date
            or selection.session.closed_at != snapshot.quote_timestamp
            or expected_selection_fingerprint
            != governed.calendar_selection_fingerprint
            or replayed_quote.review_receipt_sha256
            != context.provider_evidence_sha256
            or context.authorization_consumption.authorization_handoff_id
            != authorization.handoff_id
            or context.authorization_reservation.authorization_handoff_id
            != authorization.handoff_id
            or context.authorization_reservation.authorization_handoff_fingerprint
            != authorization.fingerprint
            or context.authorization_reservation.price_blind_input_fingerprint
            != loaded.artifact.fingerprint
            or context.authorization_reservation.request_fingerprint
            != context.market_reference_request.request_fingerprint
            or context.authorization_consumption.reservation_fingerprint
            != context.authorization_reservation.fingerprint
            or context.authorization_consumption.authorization_handoff_fingerprint
            != authorization.fingerprint
            or context.authorization_consumption.price_blind_input_fingerprint
            != loaded.artifact.fingerprint
            or context.authorization_consumption.request_fingerprint
            != context.market_reference_request.request_fingerprint
            or context.authorization_consumption.market_access_result_fingerprint
            != context.market_access_result.fingerprint
            or context.authorization_consumption.quote_fingerprint
            != replayed_quote.fingerprint
            or not (
                _timestamp(authorization.transitioned_at, "authorization transition")
                <= source_retrieved
                <= reviewed_at
                <= request_started
                <= retrieved_at
            )
            or _timestamp(replayed_quote.quote_timestamp, "quote timestamp")
            > source_retrieved
            or not (
                date.fromisoformat(replayed_quote.trading_date)
                <= date.fromisoformat(replayed_quote.source_published_date)
                <= source_retrieved.date()
            )
        ):
            raise ValuationHandoffValidationError(
                "Reviewed-file evidence replay changed its governed identity"
            )
        return
    authority = load_market_access_authority(graph.component_lock_path)
    registration = next(
        (
            item
            for item in authority.provider_registry.registrations
            if item.provider_id == receipt.provider_id
            and item.provider_version == receipt.provider_version
            and item.fingerprint == governed.provider_registration_sha256
        ),
        None,
    )
    if (
        registration is None
        or registration.content_type != raw["content_type"]
        or registration.evidence_mode != governed.evidence_mode
        or registration.adapter_sha256 != governed.adapter_sha256
        or registration.parser_sha256 != governed.parser_sha256
        or registration.price_basis != receipt.price_basis
        or registration.session_kind != receipt.session_kind
        or registration.endpoint_id != receipt.endpoint
        or receipt.trading_calendar_id not in registration.trading_calendar_ids
        or snapshot.security["mic"] not in registration.supported_mics
        or authority.authority_sha256 != governed.authority_sha256
        or authority.provider_registry.fingerprint
        != governed.provider_registry_sha256
        or canonical_sha256(authority.calendar_registry.to_dict())
        != governed.calendar_registry_sha256
    ):
        raise ValuationHandoffValidationError("Raw evidence content type is not registered")
    if raw_bytes is None:
        raise ValuationHandoffValidationError("Raw market evidence is unavailable for replay")
    from .valuation_market_authority_types import RawMarketResponse
    from .valuation_market_runtime import parse_locked_raw_response

    try:
        replayed_quote, replayed_sha256 = parse_locked_raw_response(
            RawMarketResponse(
                raw_response=raw_bytes,
                content_type=raw["content_type"],
                transport_metadata={
                    "adapter_kind": registration.adapter_kind,
                    "endpoint_id": registration.endpoint_id,
                },
            ),
            registration=registration,
        )
    except (TypeError, ValueError) as exc:
        raise ValuationHandoffValidationError("Locked market parser replay failed") from exc
    expected_quote = {
        "security_id": receipt.security_id,
        "ticker": receipt.ticker,
        "exchange": receipt.exchange,
        "share_class": receipt.share_class,
        "trading_calendar_id": receipt.trading_calendar_id,
        "trading_date": receipt.trading_date,
        "quote_timestamp": receipt.quote_timestamp,
        "session_kind": receipt.session_kind,
        "session_status": receipt.session_status,
        "instrument_status": receipt.instrument_status,
        "price_basis": receipt.price_basis,
        "quote_price": receipt.quote_price,
        "quote_currency": receipt.quote_currency,
    }
    if (
        replayed_sha256 != raw["raw_response_sha256"]
        or replayed_quote.to_dict() != expected_quote
    ):
        raise ValuationHandoffValidationError(
            "Locked market parser replay changed the governed quote"
        )
    request = context.market_access_result.request
    if request is None:
        raise ValuationHandoffValidationError("Market calendar replay lacks its Request")
    from .valuation_market_calendar import (
        MarketCalendarError,
        select_latest_completed_session,
    )

    try:
        selection = select_latest_completed_session(
            authority,
            mic=snapshot.security["mic"],
            cutoff_date=date.fromisoformat(snapshot.data_cutoff_date),
            observed_at=datetime.fromisoformat(
                request.request_started_at.replace("Z", "+00:00")
            ),
        )
    except (MarketCalendarError, TypeError, ValueError) as exc:
        raise ValuationHandoffValidationError("Locked market calendar replay failed") from exc
    if (
        selection.calendar_id != receipt.trading_calendar_id
        or selection.dataset_sha256 != governed.calendar_dataset_sha256
        or selection.fingerprint != governed.calendar_selection_fingerprint
        or selection.session.trading_date != receipt.trading_date
        or selection.session.trading_date != receipt.latest_completed_session_date
        or selection.session.closed_at != receipt.quote_timestamp
    ):
        raise ValuationHandoffValidationError(
            "Locked market calendar replay changed the governed session"
        )


def _validate_market_snapshot(
    graph: Any,
    snapshot: MarketReferenceSnapshot,
    handoffs: dict[str, Contract],
    bundles: dict[str, Contract],
) -> None:
    if (
        snapshot.market_policy_id != MARKET_REFERENCE_POLICY_ID
        or snapshot.market_policy_version != MARKET_REFERENCE_POLICY_VERSION
    ):
        raise ValuationHandoffValidationError("MarketReferenceSnapshot policy mismatch")
    authorization = handoffs.get(snapshot.authorization_handoff_id)
    if authorization is None or authorization.state != "market_reference_allowed":
        raise ValuationHandoffValidationError("Market reference lacks price-blind authorization")
    contexts = tuple(
        item
        for item in graph.market_reference_validation_contexts
        if item.market_access_result.fingerprint == snapshot.market_access_result_fingerprint
        and item.market_access_result.authorization_handoff_id == authorization.handoff_id
    )
    if len(contexts) != 1:
        raise ValuationHandoffValidationError("Market reference lacks one exact validation context")
    context = contexts[0]
    access = context.market_access_result
    request = access.request
    governed = access.receipt
    security_compilation = context.security_compilation_result
    security_decision = security_compilation.decision
    share_decision = context.share_basis_decision
    if request is None or governed is None or security_decision is None:
        raise ValuationHandoffValidationError("Market reference context is not eligible")
    receipt = governed.receipt
    if (
        snapshot.issuer_id != authorization.issuer_id
        or snapshot.data_cutoff_date != authorization.data_cutoff_date
        or snapshot.authorization_handoff_fingerprint != authorization.fingerprint
        or snapshot.component_lock_sha256 != file_sha256(graph.component_lock_path)
        or snapshot.price_blind_input_fingerprint != authorization.price_blind_input_fingerprint
        or snapshot.protected_mckinsey_sha256 != authorization.protected_mckinsey_sha256
        or snapshot.protected_penman_assumptions_sha256
        != authorization.protected_penman_assumptions_sha256
    ):
        raise ValuationHandoffValidationError("Market reference changed protected authorization")
    artifact = context.price_blind_artifact.to_dict()
    if (
        artifact["component_lock_sha256"] != snapshot.component_lock_sha256
        or artifact["price_blind_input_fingerprint"] != snapshot.price_blind_input_fingerprint
        or artifact["protected_mckinsey_sha256"] != snapshot.protected_mckinsey_sha256
        or artifact["protected_penman_assumptions_sha256"]
        != snapshot.protected_penman_assumptions_sha256
    ):
        raise ValuationHandoffValidationError("Snapshot does not replay the price-blind artifact")
    if (
        snapshot.market_quote_request["request_id"] != request.request_id
        or snapshot.market_quote_request["request_fingerprint"] != request.request_fingerprint
        or snapshot.governed_market_quote_receipt["receipt_id"] != receipt.receipt_id
        or snapshot.governed_market_quote_receipt["receipt_fingerprint"] != governed.fingerprint
    ):
        raise ValuationHandoffValidationError("Snapshot Request or Receipt lineage mismatch")
    expected_authority = {
        "authority_sha256": governed.authority_sha256,
        "provider_registry_sha256": governed.provider_registry_sha256,
        "provider_registration_sha256": governed.provider_registration_sha256,
        "adapter_sha256": governed.adapter_sha256,
        "parser_sha256": governed.parser_sha256,
        "calendar_registry_sha256": governed.calendar_registry_sha256,
        "calendar_dataset_sha256": governed.calendar_dataset_sha256,
        "calendar_selection_fingerprint": governed.calendar_selection_fingerprint,
        "provider_evidence_sha256": (
            context.provider_evidence_sha256 or governed.fingerprint
        ),
    }
    if dict(snapshot.authority_lineage) != expected_authority:
        raise ValuationHandoffValidationError("Snapshot market authority lineage mismatch")
    expected_security = {
        "security_id": security_decision.security_id,
        "ticker": security_decision.ticker,
        "mic": security_decision.exchange,
        "share_class": security_decision.share_class,
        "security_compilation_fingerprint": security_compilation.fingerprint,
        "security_evidence_closure_sha256": (security_compilation.evidence_closure.closure_sha256),
    }
    if dict(snapshot.security) != expected_security:
        raise ValuationHandoffValidationError("Snapshot security lineage mismatch")
    if date.fromisoformat(snapshot.trading_date) > date.fromisoformat(snapshot.data_cutoff_date):
        raise ValuationHandoffValidationError("Market quote follows the data cutoff")
    quote_time = datetime.fromisoformat(snapshot.quote_timestamp.replace("Z", "+00:00"))
    retrieved = datetime.fromisoformat(snapshot.quote_retrieved_at.replace("Z", "+00:00"))
    if (
        quote_time.date().isoformat() != snapshot.trading_date
        or retrieved < quote_time
        or snapshot.trading_date != receipt.trading_date
        or snapshot.quote_timestamp != receipt.quote_timestamp
        or snapshot.quote_retrieved_at != receipt.retrieved_at
        or snapshot.quote_price_decimal != receipt.quote_price
        or snapshot.quote_currency != receipt.quote_currency
        or snapshot.evidence_mode != governed.evidence_mode
    ):
        raise ValuationHandoffValidationError("Market quote timestamp or retrieval time mismatch")
    if snapshot.evidence_mode in {"recorded_fixture", "loopback_fixture"}:
        if (
            snapshot.usage_scope != "test_only"
            or snapshot.source_authority_kind != "human_reviewed_file"
        ):
            raise ValuationHandoffValidationError("Fixture market evidence is test-only")
    elif snapshot.evidence_mode == "human_reviewed_file":
        if (
            snapshot.usage_scope != "release_candidate"
            or snapshot.source_authority_kind != "human_reviewed_file"
        ):
            raise ValuationHandoffValidationError(
                "Reviewed-file evidence is release-candidate only"
            )
    elif (
        snapshot.evidence_mode != "governed_vendor"
        or snapshot.usage_scope != "production"
        or snapshot.source_authority_kind != "governed_vendor"
    ):
        raise ValuationHandoffValidationError("Governed-vendor evidence usage is invalid")
    numeric = snapshot.numeric_evidence
    if (
        numeric["authoritative_decimal"] != snapshot.quote_price_decimal
        or (
            snapshot.source_authority_kind == "human_reviewed_file"
            and (
                numeric["encoding"] != "canonical_decimal"
                or numeric["binary64_hex"] is not None
            )
        )
    ):
        raise ValuationHandoffValidationError("Market numeric evidence does not replay")
    _validate_raw_evidence(graph, snapshot, context)
    if snapshot.raw_evidence[
        "raw_response_sha256"
    ] != governed.raw_response_sha256 or snapshot.raw_evidence[
        "parser_replay_fingerprint"
    ] != parser_replay_fingerprint(snapshot.to_dict(), receipt):
        raise ValuationHandoffValidationError("Raw/parser replay fingerprint mismatch")

    documents = _index(graph.documents, "document_id")
    facts = _index(graph.facts, "fact_id")
    calculations = _index(graph.calculations, "calculation_id")
    quote_document = documents.get(snapshot.quote_source_document_id)
    quote_fact = facts.get(snapshot.quote_fact_id)
    share = snapshot.share_basis
    market_equity = snapshot.market_equity
    current_share_fact = facts.get(share["shares_outstanding_fact_id"])
    calculation = calculations.get(market_equity["calculation_id"])
    if (
        quote_document is None
        or quote_document.authority_level != "market_reference"
        or quote_document.content_sha256 != governed.raw_response_sha256
        or quote_document.issuer_id != snapshot.issuer_id
        or quote_document.document_type != "market-quote"
        or dict(quote_document.period)
        != {"start": None, "end": snapshot.trading_date}
    ):
        raise ValuationHandoffValidationError("Quote source is not a market reference")
    expected_source_retrieved_at = (
        context.reviewed_quote.source_retrieved_at
        if snapshot.evidence_mode == "human_reviewed_file"
        and context.reviewed_quote is not None
        else receipt.retrieved_at
    )
    if quote_document.retrieved_at != expected_source_retrieved_at:
        raise ValuationHandoffValidationError(
            "Quote SourceDocument retrieval does not replay its evidence mode"
        )
    if snapshot.evidence_mode == "human_reviewed_file":
        reviewed_quote = context.reviewed_quote
        if (
            reviewed_quote is None
            or quote_document.document_id
            != f"doc:{snapshot.issuer_id}:reviewed-market:{governed.raw_response_sha256[:24]}"
            or quote_document.issuer_id != reviewed_quote.issuer_id
            or quote_document.document_type != "market-quote"
            or dict(quote_document.period)
            != {"start": None, "end": reviewed_quote.trading_date}
            or quote_document.published_date != reviewed_quote.source_published_date
            or quote_document.retrieved_at != reviewed_quote.source_retrieved_at
            or quote_document.source_url != reviewed_quote.source_url
        ):
            raise ValuationHandoffValidationError(
                "Reviewed quote SourceDocument is not an exact receipt projection"
            )
    quote_retrieved_date = datetime.fromisoformat(
        quote_document.retrieved_at.replace("Z", "+00:00")
    ).date()
    if not (
        date.fromisoformat(snapshot.trading_date)
        <= date.fromisoformat(quote_document.published_date)
        <= quote_retrieved_date
    ):
        raise ValuationHandoffValidationError(
            "Market source publication does not match its quote chronology"
        )
    if quote_fact is None or current_share_fact is None or calculation is None:
        raise ValuationHandoffValidationError("Market reference has dangling numeric evidence")
    if snapshot.evidence_mode == "human_reviewed_file" and quote_fact.fact_id != (
        f"fact:{snapshot.issuer_id}:reviewed-close:{snapshot.trading_date}:"
        f"{governed.raw_response_sha256[:16]}"
    ):
        raise ValuationHandoffValidationError(
            "Reviewed quote Fact identity is not deterministic"
        )
    if (
        quote_fact.issuer_id != snapshot.issuer_id
        or quote_fact.concept != "market_quote_close"
        or quote_fact.source_document_id != quote_document.document_id
        or quote_fact.source_locator != snapshot.quote_source_locator
        or quote_fact.value_type != "number"
        or quote_fact.unit != "currency_per_share"
        or quote_fact.currency != snapshot.quote_currency
        or Decimal(str(quote_fact.value)) != Decimal(snapshot.quote_price_decimal)
        or quote_fact.period["end"] != snapshot.trading_date
        or quote_fact.period["start"] is not None
        or quote_fact.derivation is not None
        or quote_fact.parent_fact_ids
        or quote_fact.confidence != "high"
    ):
        raise ValuationHandoffValidationError("Quote Fact does not round-trip the market quote")
    expected_locator = (
        f"market://{request.request_id}/{receipt.receipt_id}/{governed.parser_sha256}"
    )
    if snapshot.quote_source_locator != expected_locator:
        raise ValuationHandoffValidationError("Quote Fact locator does not bind parser lineage")

    _ = bundles[authorization.research_bundle_id]
    if (
        share["decision_id"] != share_decision.decision_id
        or share["decision_fingerprint"] != share_decision.fingerprint
        or share["basis_kind"] != share_decision.basis_kind
        or share["evidence_kind"] != share_decision.evidence_kind
        or share["as_of_date"] != share_decision.as_of_date
        or share["quote_date"] != share_decision.quote_date
        or share["shares_outstanding_fact_id"] != share_decision.share_fact_id
        or share["split_factor_decimal"] != share_decision.split_factor
        or share["as_of_date"] != snapshot.trading_date
        or Decimal(str(current_share_fact.value))
        != Decimal(share["current_common_shares_outstanding_decimal"])
    ):
        raise ValuationHandoffValidationError("Snapshot share-basis decision mismatch")
    evidence_bindings = share["corporate_action_evidence_bindings"]
    if {item["object_id"] for item in evidence_bindings} != set(
        share_decision.corporate_action_evidence_ids
    ):
        raise ValuationHandoffValidationError("Corporate-action evidence set mismatch")
    cutoff = date.fromisoformat(snapshot.data_cutoff_date)
    for binding in evidence_bindings:
        item = _contract_object(graph, binding["contract_type"], binding["object_id"])
        if item is None or item.fingerprint != binding["fingerprint"]:
            raise ValuationHandoffValidationError("Corporate-action evidence fingerprint mismatch")
        if binding["contract_type"] == "SourceDocument":
            sources = (item,)
        elif binding["contract_type"] == "Fact":
            sources = (documents[item.source_document_id],)
        else:
            claim_facts = tuple(
                facts[fact_id]
                for fact_id in (*item.supporting_fact_ids, *item.counterevidence_fact_ids)
            )
            sources = tuple(documents[fact.source_document_id] for fact in claim_facts)
        if not sources or any(
            source.authority_level not in {"primary_regulatory", "company_primary"}
            or date.fromisoformat(source.published_date) > cutoff
            for source in sources
        ):
            raise ValuationHandoffValidationError("Corporate-action evidence is not formal")
    share_evidence = _validate_current_share_lineage(
        graph=graph,
        share_fact=current_share_fact,
        evidence_kind=share_decision.evidence_kind,
        trading_date=snapshot.trading_date,
        data_cutoff_date=snapshot.data_cutoff_date,
        security_compilation_result=security_compilation,
        share_basis_decision=share_decision,
        claim_control_authority=context.claim_control_authority,
        expected_closure=context.current_share_compilation_result.evidence_closure,
    )
    share_roots = set(
        share_evidence.ultimate_numeric_root_fact_ids
        if isinstance(share_evidence, CurrentShareEvidenceClosureV2)
        else share_evidence.numeric_root_fact_ids
    )
    authority = context.claim_control_authority
    claim_roots = set(
        (
            *authority.included_option_root_fact_ids,
            *authority.excluded_option_root_fact_ids,
            *authority.blocked_option_root_fact_ids,
        )
    )
    if share_roots.intersection(claim_roots):
        raise ValuationHandoffValidationError(
            "Current-share numeric roots overlap Phase 5C claim-control roots"
        )
    ordered_share_roots = tuple(sorted(share_roots))
    ordered_excluded_roots = tuple(sorted(authority.excluded_option_root_fact_ids))
    claim_check = share["claim_control_check"]
    if (
        tuple(claim_check["current_share_numeric_root_fact_ids"]) != ordered_share_roots
        or claim_check["included_claim_root_fact_ids"]
        or tuple(claim_check["excluded_claim_root_fact_ids"]) != ordered_excluded_roots
        or claim_check["blocked_claim_root_fact_ids"]
        or claim_check["overlap_fact_ids"]
        or claim_check["check_fingerprint"]
        != claim_control_fingerprint(
            price_blind_input_fingerprint=snapshot.price_blind_input_fingerprint,
            share_basis_decision_fingerprint=share_decision.fingerprint,
            claim_control_authority_fingerprint=authority.fingerprint,
            current_share_numeric_root_fact_ids=ordered_share_roots,
            excluded_claim_root_fact_ids=ordered_excluded_roots,
        )
    ):
        raise ValuationHandoffValidationError("Claim-control check does not replay")

    future = snapshot.future_kernel_request_v2
    if (
        future["share_denominator_fact_id"] != current_share_fact.fact_id
        or future["share_denominator_kind"] != "current_common_shares_outstanding"
        or future["share_denominator_evidence_kind"] != share_decision.evidence_kind
        or future["mapping_fingerprint"]
        != future_request_v2_mapping_fingerprint(
            price_blind_input_fingerprint=snapshot.price_blind_input_fingerprint,
            shares_outstanding_fact_id=current_share_fact.fact_id,
            evidence_kind=share_decision.evidence_kind,
        )
    ):
        raise ValuationHandoffValidationError("Future kernel request-v2 mapping does not replay")

    if snapshot.evidence_mode == "human_reviewed_file" and (
        calculation.calculation_id
        != (
            f"calc:{snapshot.issuer_id}:market-equity:{snapshot.trading_date}:"
            f"{governed.raw_response_sha256[:16]}"
        )
        or calculation.calculator_id != "reviewed-close-times-current-common-shares"
        or calculation.calculator_version != "1.0.0"
        or calculation.generated_at != receipt.retrieved_at
    ):
        raise ValuationHandoffValidationError(
            "Reviewed market-equity CalculationResult identity changed"
        )
    if (
        calculation.issuer_id != snapshot.issuer_id
        or calculation.concept != "market_equity_value"
        or calculation.value_type != "number"
        or calculation.input_assumption_ids
        or calculation.input_calculation_ids
        or calculation.input_period_ids
        or set(calculation.input_fact_ids) != {quote_fact.fact_id, current_share_fact.fact_id}
        or dict(calculation.input_bindings)
        != {"current_common_shares": current_share_fact.fact_id, "quote": quote_fact.fact_id}
        or calculation.currency != market_equity["currency"]
        or calculation.unit != market_equity["unit"]
        or calculation.calculation_id != market_equity["calculation_id"]
        or dict(calculation.period)
        != {"start": None, "end": snapshot.trading_date}
    ):
        raise ValuationHandoffValidationError("Market-equity CalculationResult is not canonical")
    from .valuation_market_snapshot import _calculation_code_sha256

    if (
        snapshot.evidence_mode == "human_reviewed_file"
        and calculation.code_sha256 != _calculation_code_sha256()
    ):
        raise ValuationHandoffValidationError(
            "Market-equity CalculationResult code identity changed"
        )
    if market_equity["currency"] != snapshot.quote_currency:
        raise ValuationHandoffValidationError("Market-equity currency mismatch")
    from .valuation_market_provider import exact_decimal_product

    normalized_shares = normalize_value(current_share_fact.value, current_share_fact.unit)
    expected_units = exact_decimal_product(
        snapshot.quote_price_decimal,
        format(normalized_shares, "f"),
    )
    snapshot_units = Decimal(market_equity["value_decimal"])
    calculation_units = normalize_value(calculation.value, calculation.unit)
    if expected_units != snapshot_units or snapshot_units != calculation_units:
        raise ValuationHandoffValidationError("Market-equity value failed exact round-trip")
    if (
        market_equity["unit"] != "currency_units"
        or unit_spec(market_equity["unit"]).family != "monetary"
    ):
        raise ValuationHandoffValidationError("Market-equity value must use a monetary unit")
    expected_closure = market_evidence_closure_sha256(
        graph,
        snapshot.to_dict(),
        authorization,
        context,
    )
    if snapshot.market_evidence_closure_sha256 != expected_closure:
        raise ValuationHandoffValidationError("Market-evidence closure does not replay")


def validate_valuation_handoff_contracts(graph: Any) -> None:
    """Validate caller-supplied Phase 5A contracts without building or mutating them."""

    bundles = _index(graph.research_bundles, "bundle_id")
    candidates = _index(graph.valuation_assumption_candidates, "candidate_id")
    decisions = _index(graph.valuation_assumption_review_decisions, "decision_id")
    snapshots = _index(graph.market_reference_snapshots, "snapshot_id")
    handoffs = _index(graph.valuation_handoffs, "handoff_id")

    for candidate in graph.valuation_assumption_candidates:
        _validate_candidate(graph, candidate, bundles)
    _validate_decisions(graph, candidates)
    _validate_handoffs(graph, bundles, candidates, decisions, snapshots)
    authorization_ids = [
        snapshot.authorization_handoff_id for snapshot in graph.market_reference_snapshots
    ]
    if len(authorization_ids) != len(set(authorization_ids)):
        raise ValuationHandoffValidationError(
            "One market_reference_allowed Handoff cannot authorize two Snapshots"
        )
    for snapshot in graph.market_reference_snapshots:
        _validate_market_snapshot(graph, snapshot, handoffs, bundles)
