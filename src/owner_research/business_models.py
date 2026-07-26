from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date

from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    BusinessModelSnapshot,
    Claim,
    Fact,
    FiscalPeriod,
    SegmentDefinition,
    SegmentSnapshot,
    SourceDocument,
)
from .fingerprints import canonical_sha256

BUSINESS_ATTRIBUTE_ROLES: dict[str, frozenset[str]] = {
    "customer": frozenset({"customer_identity", "demand_recurrence", "customer_concentration"}),
    "value_proposition": frozenset({"purchase_reason"}),
    "revenue_model": frozenset({"revenue_formation", "pricing_method"}),
    "cost_structure": frozenset(
        {"cost_structure", "capital_requirements", "supplier_concentration"}
    ),
    "distribution": frozenset({"distribution_method"}),
    "key_resource": frozenset({"key_resources"}),
    "key_partner": frozenset({"key_partners"}),
    "regulatory_dependency": frozenset({"regulatory_dependencies"}),
}
BUSINESS_COMPONENT_TYPES = frozenset(BUSINESS_ATTRIBUTE_ROLES)
CORE_SCOPE_COMPONENTS = frozenset(
    {"customer", "value_proposition", "revenue_model", "cost_structure", "distribution"}
)
SHAREABLE_COMPONENTS = frozenset(
    {"key_resource", "key_partner", "regulatory_dependency"}
)
NOT_APPLICABLE_COMPONENTS = frozenset({"key_partner", "regulatory_dependency"})
OFFICIAL_AUTHORITIES = frozenset({"primary_regulatory", "company_primary"})


class BusinessModelBuildError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AttributeEvidenceInput:
    role: str
    fact_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    review_decision_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BusinessComponentInput:
    component_type: str
    scope: Mapping[str, object]
    attribute_evidence_bindings: tuple[AttributeEvidenceInput, ...]


@dataclass(frozen=True, slots=True)
class NotApplicableInput:
    component_type: str
    scope: Mapping[str, object]
    claim_id: str
    review_decision_id: str


@dataclass(frozen=True, slots=True)
class SharedScopeInput:
    component_type: str
    covered_scopes: tuple[Mapping[str, object], ...]
    claim_id: str
    review_decision_id: str


@dataclass(frozen=True, slots=True)
class MissingCoverageInput:
    component_type: str
    scope: Mapping[str, object]
    reasons: tuple[str, ...]


def _scope_key(scope: Mapping[str, object]) -> str:
    return canonical_sha256(dict(scope))


def _scope_id(issuer_id: str, scope: Mapping[str, object]) -> str:
    return f"business-scope:{issuer_id}:{_scope_key(scope)[:20]}"


def _issuer_scope() -> dict[str, object]:
    return {
        "scope_type": "issuer_wide",
        "segment_definition_ids": [],
        "business_unit": None,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }


def _segment_scope(segment: SegmentDefinition) -> dict[str, object]:
    return {
        "scope_type": "segment_specific",
        "segment_definition_ids": [segment.segment_id],
        "business_unit": segment.normalized_name,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }


def build_business_model_snapshot(
    *,
    issuer_id: str,
    as_of_date: str,
    source_documents: tuple[SourceDocument, ...],
    fiscal_periods: tuple[FiscalPeriod, ...],
    segment_definitions: tuple[SegmentDefinition, ...],
    segment_snapshots: tuple[SegmentSnapshot, ...],
    facts: tuple[Fact, ...],
    claims: tuple[Claim, ...],
    analytical_candidates: tuple[AnalyticalClaimCandidate, ...],
    claim_review_decisions: tuple[AnalyticalClaimReviewDecision, ...],
    components: tuple[BusinessComponentInput, ...],
    product_market_materiality_claim_ids: tuple[str, ...] = (),
    not_applicable_inputs: tuple[NotApplicableInput, ...] = (),
    shared_scope_inputs: tuple[SharedScopeInput, ...] = (),
    missing_coverage_inputs: tuple[MissingCoverageInput, ...] = (),
) -> BusinessModelSnapshot:
    cutoff = date.fromisoformat(as_of_date)
    documents = {item.document_id: item for item in source_documents}
    periods = {item.period_id: item for item in fiscal_periods}
    segments = {item.segment_id: item for item in segment_definitions}
    facts_by_id = {item.fact_id: item for item in facts}
    claims_by_id = {item.claim_id: item for item in claims}
    candidates = {item.candidate_id: item for item in analytical_candidates}
    decisions = {item.decision_id: item for item in claim_review_decisions}
    decision_by_claim = {
        item.output_claim_id: item
        for item in claim_review_decisions
        if item.decision == "confirmed" and item.output_claim_id is not None
    }
    used_documents: set[str] = set()

    def reviewed_candidate(claim_id: str, decision_id: str) -> AnalyticalClaimCandidate:
        try:
            decision = decisions[decision_id]
            claim = claims_by_id[claim_id]
            candidate = candidates[decision.candidate_id]
        except KeyError as exc:
            raise BusinessModelBuildError("reviewed analytical evidence is missing") from exc
        if (
            decision.decision != "confirmed"
            or decision.output_claim_id != claim_id
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or decision_by_claim.get(claim_id) != decision
        ):
            raise BusinessModelBuildError("analytical review decision does not confirm the Claim")
        if claim.issuer_id != issuer_id or candidate.issuer_id != issuer_id:
            raise BusinessModelBuildError("analytical evidence issuer mismatch")
        if (
            date.fromisoformat(claim.as_of_date) > cutoff
            or date.fromisoformat(candidate.as_of_date) > cutoff
        ):
            raise BusinessModelBuildError("analytical evidence follows cutoff")
        for fact_id in (*claim.supporting_fact_ids, *claim.counterevidence_fact_ids):
            try:
                fact = facts_by_id[fact_id]
                document = documents[fact.source_document_id]
            except KeyError as exc:
                raise BusinessModelBuildError("analytical Claim evidence is missing") from exc
            if fact.issuer_id != issuer_id or document.issuer_id != issuer_id:
                raise BusinessModelBuildError("analytical Claim evidence issuer mismatch")
            if date.fromisoformat(document.published_date) > cutoff:
                raise BusinessModelBuildError("analytical evidence source follows cutoff")
            used_documents.add(document.document_id)
        return candidate

    eligible: list[tuple[date, int, SegmentSnapshot, FiscalPeriod]] = []
    for snapshot in segment_snapshots:
        if snapshot.issuer_id != issuer_id or snapshot.fiscal_period_id not in periods:
            continue
        period = periods[snapshot.fiscal_period_id]
        period_end = date.fromisoformat(period.cumulative_end)
        if period_end > cutoff:
            continue
        if any(
            document_id not in documents
            or date.fromisoformat(documents[document_id].published_date) > cutoff
            for document_id in period.source_document_ids
        ):
            continue
        eligible.append((period_end, period.restatement_version, snapshot, period))
    material_scopes: list[dict[str, object]] = []
    selected_snapshot: SegmentSnapshot | None = None
    scope_resolution_blocked = False
    if eligible:
        eligible.sort(key=lambda item: (item[0], item[1], item[2].snapshot_id))
        latest_key = eligible[-1][:2]
        latest = [item for item in eligible if item[:2] == latest_key]
        if len(latest) != 1:
            scope_resolution_blocked = True
        else:
            _, _, selected_snapshot, period = latest[0]
            if selected_snapshot.status != "complete":
                scope_resolution_blocked = True
            reportable = [
                segments[segment_id]
                for segment_id in selected_snapshot.segment_definition_ids
                if segment_id in segments and segments[segment_id].segment_type == "reportable"
            ]
            effective_end = date.fromisoformat(period.cumulative_end)
            reportable = [
                segment
                for segment in reportable
                if date.fromisoformat(segment.effective_period["start"])
                <= effective_end
                <= date.fromisoformat(segment.effective_period["end"])
            ]
            for segment in reportable:
                for document_id in segment.source_document_ids:
                    if document_id not in documents or date.fromisoformat(
                        documents[document_id].published_date
                    ) > cutoff:
                        scope_resolution_blocked = True
                    else:
                        used_documents.add(document_id)
            if len(reportable) == 1:
                scope = _issuer_scope()
                material_scopes.append(
                    {
                        "scope_id": _scope_id(issuer_id, scope),
                        "scope": scope,
                        "derivation": "single_reportable_segment",
                        "segment_snapshot_id": selected_snapshot.snapshot_id,
                        "segment_definition_ids": [reportable[0].segment_id],
                        "materiality_claim_id": None,
                    }
                )
            elif len(reportable) > 1:
                for segment in reportable:
                    scope = _segment_scope(segment)
                    material_scopes.append(
                        {
                            "scope_id": _scope_id(issuer_id, scope),
                            "scope": scope,
                            "derivation": "reportable_segment",
                            "segment_snapshot_id": selected_snapshot.snapshot_id,
                            "segment_definition_ids": [segment.segment_id],
                            "materiality_claim_id": None,
                        }
                    )
            else:
                scope_resolution_blocked = True
            for document_id in period.source_document_ids:
                used_documents.add(document_id)
    else:
        scope_resolution_blocked = True

    for claim_id in product_market_materiality_claim_ids:
        decision = decision_by_claim.get(claim_id)
        if decision is None:
            raise BusinessModelBuildError("product-market materiality Claim is not confirmed")
        candidate = reviewed_candidate(claim_id, decision.decision_id)
        if candidate.claim_role != "support" or candidate.scope["scope_type"] != "product_market":
            raise BusinessModelBuildError(
                "product-market materiality Claim has invalid role or scope"
            )
        scope = dict(candidate.scope)
        material_scopes.append(
            {
                "scope_id": _scope_id(issuer_id, scope),
                "scope": scope,
                "derivation": "confirmed_product_market",
                "segment_snapshot_id": None,
                "segment_definition_ids": tuple(scope["segment_definition_ids"]),
                "materiality_claim_id": claim_id,
            }
        )
    scope_by_key = {_scope_key(item["scope"]): item for item in material_scopes}
    if len(scope_by_key) != len(material_scopes):
        raise BusinessModelBuildError("duplicate material scope")

    built_components: list[dict[str, object]] = []
    claim_roles: dict[str, str] = {}
    components_by_scope_type: dict[tuple[str, str], list[str]] = {}
    component_by_type: dict[str, list[dict[str, object]]] = {}
    for component in components:
        if component.component_type not in BUSINESS_COMPONENT_TYPES:
            raise BusinessModelBuildError("unknown business component type")
        scope_key = _scope_key(component.scope)
        is_shared = (
            component.component_type in SHAREABLE_COMPONENTS
            and component.scope["scope_type"] == "issuer_wide"
        )
        if scope_key not in scope_by_key and not is_shared and material_scopes:
            raise BusinessModelBuildError("component scope is not deterministically material")
        attribute_bindings: list[dict[str, object]] = []
        aggregate_facts: set[str] = set()
        aggregate_claims: set[str] = set()
        roles: set[str] = set()
        for binding in component.attribute_evidence_bindings:
            if binding.role not in BUSINESS_ATTRIBUTE_ROLES[component.component_type]:
                raise BusinessModelBuildError("unregistered business attribute role")
            if not binding.fact_ids or not binding.claim_ids or not binding.review_decision_ids:
                raise BusinessModelBuildError(
                    "attribute binding requires Fact, Claim, and Decision"
                )
            for fact_id in binding.fact_ids:
                if fact_id not in facts_by_id or facts_by_id[fact_id].issuer_id != issuer_id:
                    raise BusinessModelBuildError("attribute binding Fact issuer mismatch")
            for claim_id in binding.claim_ids:
                decision = decision_by_claim.get(claim_id)
                if decision is None or decision.decision_id not in binding.review_decision_ids:
                    raise BusinessModelBuildError("attribute binding Claim lacks its Decision")
                candidate = reviewed_candidate(claim_id, decision.decision_id)
                if (
                    candidate.claim_role != "support"
                    or candidate.business_attribute_role != binding.role
                    or candidate.business_component_type != component.component_type
                    or _scope_key(candidate.scope) != _scope_key(component.scope)
                ):
                    raise BusinessModelBuildError("attribute Claim semantic role or scope mismatch")
                claim = claims_by_id[claim_id]
                if not set(binding.fact_ids).issubset(set(claim.supporting_fact_ids)):
                    raise BusinessModelBuildError("attribute Claim lacks bound Fact support")
                prior_role = claim_roles.setdefault(claim_id, binding.role)
                if prior_role != binding.role:
                    raise BusinessModelBuildError("one Claim cannot support multiple attributes")
            aggregate_facts.update(binding.fact_ids)
            aggregate_claims.update(binding.claim_ids)
            roles.add(binding.role)
            binding_id = canonical_sha256(
                {
                    "role": binding.role,
                    "fact_ids": sorted(binding.fact_ids),
                    "claim_ids": sorted(binding.claim_ids),
                    "review_decision_ids": sorted(binding.review_decision_ids),
                }
            )[:20]
            attribute_bindings.append(
                {
                    "binding_id": f"attribute-binding:{issuer_id}:{binding_id}",
                    "role": binding.role,
                    "fact_ids": tuple(sorted(set(binding.fact_ids))),
                    "claim_ids": tuple(sorted(set(binding.claim_ids))),
                    "review_decision_ids": tuple(sorted(set(binding.review_decision_ids))),
                }
            )
        component_hash = canonical_sha256(
            {
                "type": component.component_type,
                "scope": component.scope,
                "bindings": attribute_bindings,
            }
        )[:20]
        component_id = f"business-component:{issuer_id}:{component_hash}"
        scope_id = _scope_id(issuer_id, component.scope)
        built = {
            "component_id": component_id,
            "component_type": component.component_type,
            "scope_id": scope_id,
            "scope": dict(component.scope),
            "attribute_roles": tuple(sorted(roles)),
            "attribute_evidence_bindings": tuple(attribute_bindings),
            "fact_ids": tuple(sorted(aggregate_facts)),
            "claim_ids": tuple(sorted(aggregate_claims)),
        }
        built_components.append(built)
        components_by_scope_type.setdefault((scope_id, component.component_type), []).append(
            component_id
        )
        component_by_type.setdefault(component.component_type, []).append(built)

    shared_relations: list[dict[str, object]] = []
    shared_coverage: dict[tuple[str, str], str] = {}
    for item in shared_scope_inputs:
        if item.component_type not in SHAREABLE_COMPONENTS:
            raise BusinessModelBuildError("core components cannot use shared scope")
        candidates_for_type = [
            component
            for component in component_by_type.get(item.component_type, [])
            if component["scope"]["scope_type"] == "issuer_wide"
        ]
        if len(candidates_for_type) != 1:
            raise BusinessModelBuildError("shared scope requires exactly one issuer-wide component")
        candidate = reviewed_candidate(item.claim_id, item.review_decision_id)
        if candidate.claim_role != "support" or candidate.scope["scope_type"] != "issuer_wide":
            raise BusinessModelBuildError("shared-scope Claim must be issuer-wide support")
        covered_ids = []
        for scope in item.covered_scopes:
            key = _scope_key(scope)
            if key not in scope_by_key:
                raise BusinessModelBuildError("shared relation references a nonmaterial scope")
            scope_id = scope_by_key[key]["scope_id"]
            covered_ids.append(scope_id)
            shared_coverage[(scope_id, item.component_type)] = candidates_for_type[0][
                "component_id"
            ]
        shared_relations.append(
            {
                "component_id": candidates_for_type[0]["component_id"],
                "covered_scope_ids": tuple(sorted(set(covered_ids))),
                "claim_id": item.claim_id,
                "review_decision_id": item.review_decision_id,
            }
        )

    not_applicable: dict[tuple[str, str], NotApplicableInput] = {}
    for item in not_applicable_inputs:
        if item.component_type not in NOT_APPLICABLE_COMPONENTS:
            raise BusinessModelBuildError("component type cannot be not-applicable")
        key = _scope_key(item.scope)
        if key not in scope_by_key:
            raise BusinessModelBuildError("not-applicable scope is not material")
        candidate = reviewed_candidate(item.claim_id, item.review_decision_id)
        if (
            candidate.claim_role != "not_applicable"
            or candidate.business_component_type != item.component_type
            or candidate.business_attribute_role is not None
            or _scope_key(candidate.scope) != _scope_key(item.scope)
        ):
            raise BusinessModelBuildError("not-applicable Claim role, component, or scope mismatch")
        not_applicable[(scope_by_key[key]["scope_id"], item.component_type)] = item

    missing_by_pair = {
        (_scope_id(issuer_id, item.scope), item.component_type): item.reasons
        for item in missing_coverage_inputs
    }
    coverage: list[dict[str, object]] = []
    missing: list[str] = []
    blocked_core = False
    for material_scope in material_scopes:
        scope_id = material_scope["scope_id"]
        for component_type in sorted(BUSINESS_COMPONENT_TYPES):
            direct_components = components_by_scope_type.get(
                (scope_id, component_type), []
            )
            shared_components = (
                [shared_coverage[(scope_id, component_type)]]
                if (scope_id, component_type) in shared_coverage
                else []
            )
            component_ids = tuple(sorted(direct_components or shared_components))
            role_union = {
                role
                for component in built_components
                if component["component_id"] in component_ids
                for role in component["attribute_roles"]
            }
            if component_ids and role_union == BUSINESS_ATTRIBUTE_ROLES[component_type]:
                status = "reviewed"
                claim_ids: tuple[str, ...] = ()
                decision_ids: tuple[str, ...] = ()
                reasons: tuple[str, ...] = ()
            elif (scope_id, component_type) in not_applicable:
                item = not_applicable[(scope_id, component_type)]
                status = "not_applicable"
                claim_ids = (item.claim_id,)
                decision_ids = (item.review_decision_id,)
                reasons = ()
            else:
                status = "blocked"
                claim_ids = ()
                decision_ids = ()
                reasons = missing_by_pair.get(
                    (scope_id, component_type),
                    (f"{scope_id} lacks {component_type} evidence",),
                )
                missing.extend(reasons)
                blocked_core = blocked_core or component_type in CORE_SCOPE_COMPONENTS
            coverage.append(
                {
                    "scope_id": scope_id,
                    "component_type": component_type,
                    "status": status,
                    "component_ids": component_ids,
                    "claim_ids": claim_ids,
                    "review_decision_ids": decision_ids,
                    "missing_evidence": reasons,
                }
            )
    if scope_resolution_blocked:
        missing.append("Material business scopes are unresolved from the latest segment snapshot")
    nonofficial = {
        document_id
        for document_id in used_documents
        if documents[document_id].authority_level not in OFFICIAL_AUTHORITIES
    }
    if nonofficial:
        missing.append("Official target-company evidence is incomplete")
    if scope_resolution_blocked or blocked_core or not material_scopes:
        status = "blocked"
    elif any(item["status"] == "blocked" for item in coverage) or nonofficial:
        status = "partial"
    else:
        status = "complete"
    if not used_documents:
        raise BusinessModelBuildError("business model has no source-backed evidence")
    identifier = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "as_of_date": as_of_date,
            "material_scopes": material_scopes,
            "components": built_components,
            "coverage": coverage,
            "shared_scope_relations": shared_relations,
        }
    )[:20]
    return BusinessModelSnapshot(
        schema_version="3.0.0",
        snapshot_id=f"business-model:{issuer_id}:{identifier}",
        issuer_id=issuer_id,
        as_of_date=as_of_date,
        status=status,
        source_document_ids=tuple(sorted(used_documents)),
        segment_snapshot_ids=(selected_snapshot.snapshot_id,) if selected_snapshot else (),
        material_scopes=tuple(material_scopes),
        components=tuple(built_components),
        component_coverage=tuple(coverage),
        shared_scope_relations=tuple(shared_relations),
        missing_evidence=tuple(sorted(set(missing))),
    )
