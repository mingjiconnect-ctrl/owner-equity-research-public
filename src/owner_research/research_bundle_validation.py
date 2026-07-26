"""Phase 4E-0 validation-only integration policy.

The routines in this module validate a caller-supplied ResearchBundle.  They do not select,
construct, persist, or publish one.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import fields
from typing import Any

from .component_lock import file_sha256
from .contracts import Contract, ResearchBundle
from .fingerprints import to_json_value
from .research_bundle_policies import (
    BUNDLE_POLICY_ID,
    BUNDLE_POLICY_VERSION,
    MODULE_POLICY_BY_TYPE,
    MODULE_TYPES,
    bundle_identifier,
    bundle_payload_sha256,
    dependency_closure_sha256,
    module_artifact_sha256,
    source_graph_sha256,
)


class ResearchBundleValidationError(ValueError):
    pass


ID_ATTRIBUTES = (
    "document_id",
    "fact_id",
    "claim_id",
    "assumption_id",
    "calculation_id",
    "period_id",
    "reconciliation_id",
    "update_id",
    "artifact_id",
    # Review decisions also carry the candidate they reviewed.  The decision is
    # the graph object, so its own identifier must win over that foreign key.
    "decision_id",
    "candidate_id",
    "promotion_id",
    "segment_id",
    "snapshot_id",
    "review_id",
    "finding_id",
    "observation_id",
    "context_snapshot_id",
    "hypothesis_id",
    "statement_id",
    "commitment_id",
    "outcome_id",
    "event_id",
    "receipt_id",
    "score_id",
    "run_id",
    "bundle_id",
)

GRAPH_DOMAIN_TYPES = {
    "documents": "SourceDocument",
    "facts": "Fact",
    "claims": "Claim",
    "assumptions": "Assumption",
    "calculations": "CalculationResult",
    "periods": "FiscalPeriod",
    "reconciliations": "QuarterlyReconciliation",
    "quarterly_updates": "QuarterlyUpdate",
    "filing_artifacts": "FilingArtifact",
    "extraction_candidates": "ExtractionCandidate",
    "evidence_promotions": "EvidencePromotion",
    "segment_definitions": "SegmentDefinition",
    "segment_snapshots": "SegmentSnapshot",
    "footnote_reviews": "FootnoteReview",
    "accounting_quality_findings": "AccountingQualityFinding",
    "accounting_quality_reviews": "AccountingQualityReview",
    "context_observations": "ContextObservation",
    "competitive_context_snapshots": "CompetitiveContextSnapshot",
    "analytical_claim_candidates": "AnalyticalClaimCandidate",
    "analytical_claim_review_decisions": "AnalyticalClaimReviewDecision",
    "business_model_snapshots": "BusinessModelSnapshot",
    "competitive_advantage_hypotheses": "CompetitiveAdvantageHypothesis",
    "business_quality_reviews": "BusinessQualityReview",
    "management_statements": "ManagementStatement",
    "management_statement_candidates": "ManagementStatementCandidate",
    "management_statement_review_decisions": "ManagementStatementReviewDecision",
    "management_commitments": "ManagementCommitment",
    "management_outcomes": "ManagementOutcome",
    "capital_allocation_event_candidates": "CapitalAllocationEventCandidate",
    "capital_allocation_event_review_decisions": "CapitalAllocationEventReviewDecision",
    "capital_allocation_events": "CapitalAllocationEvent",
    "capital_allocation_outcomes": "CapitalAllocationOutcome",
    "source_search_receipts": "SourceSearchReceipt",
    "management_reviews": "ManagementReview",
    "capital_allocation_reviews": "CapitalAllocationReview",
    "scores": "Score",
    "manifests": "RunManifest",
}

MODULE_GRAPH_FIELDS = {
    "quarterly_update": "quarterly_updates",
    "segment_snapshot": "segment_snapshots",
    "footnote_review": "footnote_reviews",
    "accounting_quality_review": "accounting_quality_reviews",
    "management_review": "management_reviews",
    "business_quality_review": "business_quality_reviews",
    "capital_allocation_review": "capital_allocation_reviews",
}


def _object_id(item: Contract) -> str:
    for attribute in ID_ATTRIBUTES:
        value = getattr(item, attribute, None)
        if isinstance(value, str):
            return value
    raise ResearchBundleValidationError(f"{type(item).__name__} has no registered identifier")


def _registry(graph: Any) -> dict[str, tuple[str, Contract]]:
    result: dict[str, tuple[str, Contract]] = {}
    for field_name, contract_type in GRAPH_DOMAIN_TYPES.items():
        for item in getattr(graph, field_name):
            result[_object_id(item)] = (contract_type, item)
    return result


def _strings(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        result: set[str] = set()
        for child in value.values():
            result.update(_strings(child))
        return result
    if isinstance(value, (list, tuple)):
        result = set()
        for child in value:
            result.update(_strings(child))
        return result
    return set()


def dependency_closure(graph: Any, roots: tuple[str, ...]) -> dict[str, tuple[str, Contract]]:
    registry = _registry(graph)
    pending = list(roots)
    closure: dict[str, tuple[str, Contract]] = {}
    while pending:
        identifier = pending.pop()
        if identifier in closure:
            continue
        if identifier not in registry:
            raise ResearchBundleValidationError(
                f"ResearchBundle has a dangling dependency: {identifier}"
            )
        contract_type, item = registry[identifier]
        if contract_type == "RunManifest":
            continue
        closure[identifier] = (contract_type, item)
        for candidate in _strings(item.to_dict()):
            if candidate in registry and candidate not in closure:
                pending.append(candidate)
    return closure


def _period_for(item: Contract, periods: dict[str, Contract]) -> dict[str, str] | None:
    if hasattr(item, "review_period"):
        return dict(item.review_period)
    period_id = getattr(item, "fiscal_period_id", None) or getattr(item, "current_period_id", None)
    if period_id and period_id in periods:
        period = periods[period_id]
        return {"start": period.quarter_start, "end": period.quarter_end}
    return None


def _as_of(item: Contract, periods: dict[str, Contract]) -> str:
    direct = getattr(item, "as_of_date", None)
    if direct:
        return direct
    period = _period_for(item, periods)
    if period:
        return period["end"]
    raise ResearchBundleValidationError(f"{type(item).__name__} lacks a cutoff-safe as-of date")


def _latest(
    items: tuple[Contract, ...], periods: dict[str, Contract], cutoff: str
) -> tuple[Contract | None, bool]:
    eligible = [item for item in items if _as_of(item, periods) <= cutoff]
    if not eligible:
        return None, False

    def key(item: Contract) -> tuple[str, int, str]:
        period_id = getattr(item, "fiscal_period_id", None) or getattr(
            item, "current_period_id", None
        )
        restatement = periods[period_id].restatement_version if period_id in periods else 0
        period = _period_for(item, periods)
        period_end = period["end"] if period else _as_of(item, periods)
        return (_as_of(item, periods), restatement, period_end)

    best_key = max(key(item) for item in eligible)
    winners = [item for item in eligible if key(item) == best_key]
    return (winners[0], len(winners) > 1)


def _scope_payload(material_scope: Any) -> dict[str, Any]:
    scope = dict(material_scope["scope"])
    return {
        "scope_id": material_scope["scope_id"],
        "scope_type": scope["scope_type"],
        "segment_definition_ids": sorted(scope["segment_definition_ids"]),
        "business_unit": scope["business_unit"],
        "product_service": scope["product_service"],
        "geography": scope["geography"],
        "customer_group": scope["customer_group"],
        "channel": scope["channel"],
    }


def _issuer_scope(issuer_id: str) -> dict[str, Any]:
    return {
        "scope_id": f"scope:{issuer_id}:issuer-wide",
        "scope_type": "issuer_wide",
        "segment_definition_ids": [],
        "business_unit": None,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }


def _status_for(module_type: str, objects: list[Contract]) -> str:
    if not objects:
        return "blocked"
    states = [item.status for item in objects]
    if module_type == "footnote_review":
        if "blocked" in states:
            return "blocked"
        covered = {"reviewed", "not_disclosed", "not_applicable"}
        return "complete" if all(state in covered for state in states) else "partial"
    if "blocked" in states:
        return "blocked"
    if "partial" in states:
        return "partial"
    return "complete"


def _qualifying_documents(
    graph: Any,
    module_type: str,
    cutoff: str,
    issuer_id: str,
) -> list[Contract]:
    documents = [item for item in graph.documents if item.published_date <= cutoff]
    if module_type != "business_quality_review":
        documents = [item for item in documents if item.issuer_id == issuer_id]
    if module_type in {
        "quarterly_update",
        "segment_snapshot",
        "footnote_review",
        "accounting_quality_review",
    }:
        regulatory_forms = {"10-K", "10-K/A", "10-Q", "10-Q/A"}
        return [item for item in documents if item.document_type in regulatory_forms]
    if module_type == "management_review":
        return [
            item
            for item in documents
            if item.document_type in {"10-K", "10-K/A", "10-Q", "10-Q/A", "8-K", "DEF 14A"}
            or item.authority_level == "company_primary"
        ]
    if module_type == "capital_allocation_review":
        document_ids = {
            document_id
            for receipt in graph.source_search_receipts
            if receipt.cutoff_date == cutoff and receipt.status == "completed"
            for document_id in receipt.result_document_ids
        }
        return [item for item in documents if item.document_id in document_ids]
    return [item for item in documents if item.authority_level != "market_reference"]


def _expected_freshness(
    graph: Any, module_type: str, objects: list[Contract], periods: dict[str, Contract], cutoff: str
) -> dict[str, Any]:
    issuer_ids = {item.issuer_id for item in objects}
    if not issuer_ids:
        issuer_ids = {item.issuer_id for item in graph.manifests}
    if not issuer_ids:
        issuer_ids = {item.issuer_id for item in graph.facts}
    if not issuer_ids:
        issuer_ids = {item.issuer_id for item in graph.periods}
    if len(issuer_ids) != 1:
        return {
            "status": "blocked",
            "event_watermark_date": None,
            "qualifying_source_document_ids": [],
            "missing_evidence": [f"Cannot resolve target issuer for {module_type}"],
        }
    documents = _qualifying_documents(
        graph,
        module_type,
        cutoff,
        next(iter(issuer_ids)),
    )
    if not documents:
        return {
            "status": "blocked",
            "event_watermark_date": None,
            "qualifying_source_document_ids": [],
            "missing_evidence": [f"No policy-relevant source watermark for {module_type}"],
        }
    watermark = max(item.published_date for item in documents)
    watermark_documents = [item for item in documents if item.published_date == watermark]
    module_closure = dependency_closure(
        graph,
        tuple(_object_id(item) for item in objects),
    )
    evidence_dates = [
        item.published_date
        for contract_type, item in module_closure.values()
        if contract_type == "SourceDocument"
    ]
    as_of = max(
        evidence_dates,
        default=max((_as_of(item, periods) for item in objects), default="0001-01-01"),
    )
    return {
        "status": "current" if as_of >= watermark else "stale",
        "event_watermark_date": watermark,
        "qualifying_source_document_ids": sorted(item.document_id for item in watermark_documents),
        "missing_evidence": (
            [] if as_of >= watermark else [f"{module_type} predates source watermark {watermark}"]
        ),
    }


def _expected_non_business_objects(
    graph: Any, module_type: str, periods: dict[str, Contract], cutoff: str
) -> tuple[list[Contract], bool]:
    if module_type == "footnote_review":
        accounting, ambiguous = _latest(graph.accounting_quality_reviews, periods, cutoff)
        if accounting is None or ambiguous:
            return [], ambiguous
        return [
            item
            for item in graph.footnote_reviews
            if item.review_id in set(accounting.footnote_review_ids)
        ], False
    latest, ambiguous = _latest(getattr(graph, MODULE_GRAPH_FIELDS[module_type]), periods, cutoff)
    return ([] if latest is None else [latest]), ambiguous


def _business_expectations(
    graph: Any, periods: dict[str, Contract], cutoff: str
) -> tuple[list[tuple[dict[str, Any], list[Contract], bool]], Contract | None]:
    business_model, model_ambiguous = _latest(graph.business_model_snapshots, periods, cutoff)
    if business_model is None or model_ambiguous or not business_model.material_scopes:
        unresolved = _issuer_scope("unresolved")
        unresolved["scope_id"] = "scope:unresolved"
        unresolved["scope_type"] = "unresolved"
        return [(unresolved, [], True)], business_model
    contexts = {item.context_snapshot_id: item for item in graph.competitive_context_snapshots}
    expectations: list[tuple[dict[str, Any], list[Contract], bool]] = []
    for material_scope in business_model.material_scopes:
        scope = _scope_payload(material_scope)
        candidates = []
        for review in graph.business_quality_reviews:
            if review.business_model_snapshot_id != business_model.snapshot_id:
                continue
            context = contexts.get(review.competitive_context_snapshot_id)
            if context is not None and dict(context.scope) == dict(material_scope["scope"]):
                candidates.append(review)
        latest, ambiguous = _latest(tuple(candidates), periods, cutoff)
        expectations.append((scope, [] if latest is None else [latest], ambiguous))
    return expectations, business_model


def _normalized(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalized(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return sorted((_normalized(child) for child in value), key=repr)
    return value


def validate_research_bundle(graph: Any, bundle: ResearchBundle) -> None:
    if (
        bundle.bundle_policy_id != BUNDLE_POLICY_ID
        or bundle.bundle_policy_version != BUNDLE_POLICY_VERSION
    ):
        raise ResearchBundleValidationError("ResearchBundle policy is not registered")
    cutoff = bundle.data_cutoff_date
    if any(item.issuer_id != bundle.issuer_id for item in graph.manifests):
        raise ResearchBundleValidationError("ResearchBundle issuer does not match RunManifest")

    periods = {item.period_id: item for item in graph.periods}
    references_by_type: dict[str, list[Any]] = defaultdict(list)
    for reference in bundle.module_references:
        references_by_type[reference["module_type"]].append(reference)
    if set(references_by_type) != set(MODULE_TYPES):
        raise ResearchBundleValidationError("ResearchBundle module taxonomy is incomplete")
    for module_type, policy in MODULE_POLICY_BY_TYPE.items():
        count = len(references_by_type[module_type])
        if policy.cardinality == "exactly_one" and count != 1:
            raise ResearchBundleValidationError(f"{module_type} requires exactly one reference")

    expected: list[tuple[Any, list[Contract], bool]] = []
    for module_type in MODULE_TYPES:
        if module_type == "business_quality_review":
            expectations, _ = _business_expectations(graph, periods, cutoff)
            refs = references_by_type[module_type]
            if len(refs) != len(expectations):
                raise ResearchBundleValidationError(
                    "Business-quality references do not match current material scopes"
                )
            by_scope = {ref["scope"]["scope_id"]: ref for ref in refs}
            for scope, objects, ambiguous in expectations:
                reference = by_scope.get(scope["scope_id"])
                if reference is None:
                    raise ResearchBundleValidationError("A material business scope is missing")
                if _normalized(dict(reference["scope"])) != _normalized(scope):
                    raise ResearchBundleValidationError(
                        "Business-quality scope does not match BusinessModelSnapshot"
                    )
                expected.append((reference, objects, ambiguous))
        else:
            objects, ambiguous = _expected_non_business_objects(graph, module_type, periods, cutoff)
            reference = references_by_type[module_type][0]
            if _normalized(dict(reference["scope"])) != _normalized(
                _issuer_scope(bundle.issuer_id)
            ):
                raise ResearchBundleValidationError(f"{module_type} must use the issuer scope")
            expected.append((reference, objects, ambiguous))

    selected_roots: list[str] = []
    selected_segment_snapshot_ids: set[str] = set()
    expected_bundle_status = "complete"
    expected_missing: set[str] = set()
    for reference, objects, ambiguous in expected:
        module_type = reference["module_type"]
        identifiers = sorted(_object_id(item) for item in objects)
        if ambiguous:
            if reference["module_status"] != "blocked" or reference["object_ids"]:
                raise ResearchBundleValidationError(
                    f"Ambiguous current {module_type} must be blocked"
                )
            expected_bundle_status = "blocked"
            expected_missing.update(reference["missing_evidence"])
            objects = []
            identifiers = []
        elif sorted(reference["object_ids"]) != identifiers:
            raise ResearchBundleValidationError(f"{module_type} does not select the current object")
        selected_roots.extend(identifiers)
        if module_type == "segment_snapshot":
            selected_segment_snapshot_ids.update(identifiers)

        expected_status = _status_for(module_type, objects)
        if reference["module_status"] != expected_status:
            raise ResearchBundleValidationError(f"{module_type} module status was forged")
        object_missing = {
            issue for item in objects for issue in getattr(item, "missing_evidence", ())
        }
        if not object_missing.issubset(set(reference["missing_evidence"])):
            raise ResearchBundleValidationError(
                f"{module_type} hides module-level missing evidence"
            )
        if objects:
            expected_as_of = max(_as_of(item, periods) for item in objects)
            expected_period = _period_for(objects[0], periods)
            if module_type == "footnote_review" and expected_period is None:
                expected_period = _period_for(objects[-1], periods)
        else:
            expected_as_of = cutoff
            expected_period = None
        if reference["as_of_date"] != expected_as_of or (
            (dict(reference["period"]) if reference["period"] is not None else None)
            != expected_period
        ):
            raise ResearchBundleValidationError(f"{module_type} as-of or period mismatch")

        artifact_entries = [
            (type(item).__name__, _object_id(item), item.fingerprint) for item in objects
        ]
        if reference["artifact_sha256"] != module_artifact_sha256(artifact_entries):
            raise ResearchBundleValidationError(f"{module_type} artifact hash mismatch")
        expected_freshness = _expected_freshness(graph, module_type, objects, periods, cutoff)
        if _normalized(dict(reference["freshness"])) != _normalized(expected_freshness):
            raise ResearchBundleValidationError(f"{module_type} freshness was forged")

        if expected_status == "blocked" or expected_freshness["status"] == "blocked":
            expected_bundle_status = "blocked"
        elif expected_bundle_status != "blocked" and (
            expected_status == "partial" or expected_freshness["status"] == "stale"
        ):
            expected_bundle_status = "partial"
        expected_missing.update(reference["missing_evidence"])
        expected_missing.update(expected_freshness["missing_evidence"])

    closure = dependency_closure(graph, tuple(selected_roots))
    forbidden = {"Score", "Assumption"}
    present_forbidden = sorted({kind for kind, _ in closure.values()} & forbidden)
    if present_forbidden:
        raise ResearchBundleValidationError(
            f"ResearchBundle dependency closure contains forbidden contracts: {present_forbidden}"
        )
    for kind, item in closure.values():
        if kind == "SourceDocument" and item.published_date > cutoff:
            raise ResearchBundleValidationError(
                "ResearchBundle dependency closure contains future evidence"
            )
        if kind == "CalculationResult" and item.input_assumption_ids:
            raise ResearchBundleValidationError(
                "ResearchBundle transitively depends on an Assumption"
            )
        if (
            getattr(item, "issuer_id", bundle.issuer_id) != bundle.issuer_id
            and kind != "SourceDocument"
        ):
            raise ResearchBundleValidationError("ResearchBundle mixes issuers")

    selected_business_models = [
        item for kind, item in closure.values() if kind == "BusinessModelSnapshot"
    ]
    for business_model in selected_business_models:
        for material_scope in business_model.material_scopes:
            snapshot_id = material_scope["segment_snapshot_id"]
            if snapshot_id is not None and snapshot_id not in selected_segment_snapshot_ids:
                raise ResearchBundleValidationError(
                    "ResearchBundle business scope uses a stale SegmentSnapshot"
                )
            selected_segment_ids = {
                segment_id
                for snapshot in graph.segment_snapshots
                if snapshot.snapshot_id in selected_segment_snapshot_ids
                for segment_id in snapshot.segment_definition_ids
            }
            if not set(material_scope["segment_definition_ids"]).issubset(selected_segment_ids):
                raise ResearchBundleValidationError(
                    "ResearchBundle material scope uses a different SegmentDefinition chain"
                )

    analytical_outputs = {
        item.output_claim_id
        for item in graph.analytical_claim_review_decisions
        if item.decision == "confirmed"
    }
    business_or_capital_claims: set[str] = set()
    for identifier in selected_roots:
        kind, _ = closure[identifier]
        if kind not in {"BusinessQualityReview", "CapitalAllocationReview"}:
            continue
        branch = dependency_closure(graph, (identifier,))
        business_or_capital_claims.update(
            object_id for object_id, (branch_kind, _) in branch.items() if branch_kind == "Claim"
        )
    if business_or_capital_claims - analytical_outputs:
        raise ResearchBundleValidationError(
            "ResearchBundle contains an analytical Claim without a confirmed human Decision"
        )

    closure_entries = [
        (kind, identifier, item.fingerprint) for identifier, (kind, item) in closure.items()
    ]
    expected_dependency_hash = dependency_closure_sha256(closure_entries)
    if bundle.dependency_closure_sha256 != expected_dependency_hash:
        raise ResearchBundleValidationError("ResearchBundle dependency closure hash mismatch")
    document_entries = [
        (identifier, item.content_sha256)
        for identifier, (kind, item) in closure.items()
        if kind == "SourceDocument"
    ]
    if bundle.source_graph_sha256 != source_graph_sha256(document_entries):
        raise ResearchBundleValidationError("ResearchBundle source graph hash mismatch")
    expected_documents = sorted(
        identifier for identifier, (kind, _) in closure.items() if kind == "SourceDocument"
    )
    expected_periods = sorted(
        identifier for identifier, (kind, _) in closure.items() if kind == "FiscalPeriod"
    )
    expected_segments = sorted(
        identifier for identifier, (kind, _) in closure.items() if kind == "SegmentDefinition"
    )
    if sorted(bundle.source_document_ids) != expected_documents:
        raise ResearchBundleValidationError("ResearchBundle source_document_ids mismatch")
    if sorted(bundle.fiscal_period_ids) != expected_periods:
        raise ResearchBundleValidationError("ResearchBundle fiscal_period_ids mismatch")
    if sorted(bundle.segment_definition_ids) != expected_segments:
        raise ResearchBundleValidationError("ResearchBundle segment_definition_ids mismatch")

    expected_id = bundle_identifier(bundle.issuer_id, cutoff, expected_dependency_hash)
    if bundle.bundle_id != expected_id:
        raise ResearchBundleValidationError("ResearchBundle identifier mismatch")
    if bundle.component_lock_sha256 != file_sha256(graph.component_lock_path):
        raise ResearchBundleValidationError("ResearchBundle component lock hash mismatch")
    expected_fingerprint = bundle_payload_sha256(bundle.to_dict())
    if bundle.bundle_fingerprint != expected_fingerprint:
        raise ResearchBundleValidationError("ResearchBundle fingerprint mismatch")
    if bundle.status != expected_bundle_status:
        raise ResearchBundleValidationError("ResearchBundle status was forged")
    if set(bundle.missing_evidence) != expected_missing:
        raise ResearchBundleValidationError("ResearchBundle missing-evidence closure mismatch")

    matching_manifests = [item for item in graph.manifests if item.run_id == bundle.run_id]
    if len(matching_manifests) != 1:
        raise ResearchBundleValidationError("ResearchBundle requires one matching RunManifest")
    manifest = matching_manifests[0]
    if manifest.issuer_id != bundle.issuer_id or manifest.data_cutoff_date != cutoff:
        raise ResearchBundleValidationError("ResearchBundle RunManifest identity mismatch")
    if manifest.component_lock_sha256 != bundle.component_lock_sha256:
        raise ResearchBundleValidationError("ResearchBundle RunManifest component lock mismatch")
    if manifest.output_artifact_hashes.get("research-bundle.json") != bundle.bundle_fingerprint:
        raise ResearchBundleValidationError("RunManifest lacks the ResearchBundle output hash")


def contract_payload(contract: Contract) -> dict[str, Any]:
    """Return an ordinary payload for test tooling without exposing a builder."""

    return {field.name: to_json_value(getattr(contract, field.name)) for field in fields(contract)}
