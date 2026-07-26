"""Deterministic Phase 4E-1 ResearchBundle construction.

The builder selects evidence from an already-valid ContractGraph. It does not fetch sources,
persist artifacts, expose a CLI, invoke valuation, or publish anything.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .component_lock import file_sha256
from .contracts import ResearchBundle, RunManifest, contract_from_dict
from .research_bundle_policies import (
    BUNDLE_POLICY_ID,
    BUNDLE_POLICY_VERSION,
    MODULE_TYPES,
    bundle_identifier,
    bundle_payload_sha256,
    dependency_closure_sha256,
    module_artifact_sha256,
    source_graph_sha256,
)
from .research_bundle_validation import (
    _as_of,
    _business_expectations,
    _expected_freshness,
    _expected_non_business_objects,
    _issuer_scope,
    _object_id,
    _period_for,
    _status_for,
    dependency_closure,
)
from .validation import ContractGraph, ContractGraphError


class ResearchBundleBuildError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResearchBundleBuildResult:
    bundle: ResearchBundle
    run_manifest: RunManifest


def _module_missing_evidence(
    module_type: str,
    objects: list[Any],
    *,
    ambiguous: bool,
) -> list[str]:
    missing = {
        issue for item in objects for issue in getattr(item, "missing_evidence", ())
    }
    if ambiguous:
        missing.add(f"{module_type} current selection is ambiguous")
    elif not objects:
        missing.add(f"{module_type} current module is unavailable")
    return sorted(missing)


def _module_reference(
    graph: ContractGraph,
    *,
    module_type: str,
    objects: list[Any],
    ambiguous: bool,
    scope: dict[str, Any],
    cutoff: str,
    periods: dict[str, Any],
) -> dict[str, Any]:
    selected = [] if ambiguous else objects
    object_ids = sorted(_object_id(item) for item in selected)
    module_status = "blocked" if ambiguous else _status_for(module_type, selected)
    freshness = _expected_freshness(
        graph,
        module_type,
        selected,
        periods,
        cutoff,
    )
    return {
        "module_type": module_type,
        "object_ids": object_ids,
        "module_status": module_status,
        "as_of_date": (
            max(_as_of(item, periods) for item in selected) if selected else cutoff
        ),
        "period": _period_for(selected[0], periods) if selected else None,
        "scope": scope,
        "freshness": freshness,
        "artifact_sha256": module_artifact_sha256(
            [
                (type(item).__name__, _object_id(item), item.fingerprint)
                for item in selected
            ]
        ),
        "missing_evidence": _module_missing_evidence(
            module_type,
            selected,
            ambiguous=ambiguous,
        ),
    }


def _derive_module_references(
    graph: ContractGraph,
    *,
    issuer_id: str,
    cutoff: str,
) -> list[dict[str, Any]]:
    periods = {item.period_id: item for item in graph.periods}
    references: list[dict[str, Any]] = []
    for module_type in MODULE_TYPES:
        if module_type == "business_quality_review":
            expectations, _ = _business_expectations(graph, periods, cutoff)
            for scope, objects, ambiguous in expectations:
                references.append(
                    _module_reference(
                        graph,
                        module_type=module_type,
                        objects=objects,
                        ambiguous=ambiguous,
                        scope=scope,
                        cutoff=cutoff,
                        periods=periods,
                    )
                )
            continue
        objects, ambiguous = _expected_non_business_objects(
            graph,
            module_type,
            periods,
            cutoff,
        )
        references.append(
            _module_reference(
                graph,
                module_type=module_type,
                objects=objects,
                ambiguous=ambiguous,
                scope=_issuer_scope(issuer_id),
                cutoff=cutoff,
                periods=periods,
            )
        )
    return references


def _bundle_status(references: list[dict[str, Any]]) -> tuple[str, list[str]]:
    status = "complete"
    missing: set[str] = set()
    for reference in references:
        freshness = reference["freshness"]
        missing.update(reference["missing_evidence"])
        missing.update(freshness["missing_evidence"])
        if reference["module_status"] == "blocked" or freshness["status"] == "blocked":
            status = "blocked"
        elif status != "blocked" and (
            reference["module_status"] == "partial"
            or freshness["status"] == "stale"
        ):
            status = "partial"
    return status, sorted(missing)


def _replace_manifest_output(
    manifests: tuple[RunManifest, ...],
    *,
    run_id: str,
    bundle_fingerprint: str,
) -> tuple[tuple[RunManifest, ...], RunManifest]:
    updated: list[RunManifest] = []
    selected: RunManifest | None = None
    for manifest in manifests:
        if manifest.run_id != run_id:
            updated.append(manifest)
            continue
        output_hashes = dict(manifest.output_artifact_hashes)
        output_hashes["research-bundle.json"] = bundle_fingerprint
        selected = replace(manifest, output_artifact_hashes=output_hashes)
        updated.append(selected)
    if selected is None:
        raise ResearchBundleBuildError(f"RunManifest not found: {run_id}")
    return tuple(updated), selected


def build_research_bundle(
    graph: ContractGraph,
    *,
    run_id: str,
) -> ResearchBundleBuildResult:
    """Build and validate one Bundle plus its atomically bound RunManifest."""

    matching_manifests = [item for item in graph.manifests if item.run_id == run_id]
    if len(matching_manifests) != 1:
        raise ResearchBundleBuildError(
            f"Expected exactly one RunManifest for {run_id}; found {len(matching_manifests)}"
        )
    manifest = matching_manifests[0]
    foreign_bundles = [item for item in graph.research_bundles if item.run_id != run_id]
    if foreign_bundles:
        raise ResearchBundleBuildError(
            "Input graph contains ResearchBundles from a different run"
        )
    base_graph = replace(graph, research_bundles=())
    try:
        base_graph.validate()
    except ContractGraphError as exc:
        raise ResearchBundleBuildError(f"Input ContractGraph is invalid: {exc}") from exc

    references = _derive_module_references(
        base_graph,
        issuer_id=manifest.issuer_id,
        cutoff=manifest.data_cutoff_date,
    )
    roots = tuple(
        object_id
        for reference in references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(base_graph, roots)
    closure_entries = [
        (contract_type, object_id, item.fingerprint)
        for object_id, (contract_type, item) in closure.items()
    ]
    dependency_hash = dependency_closure_sha256(closure_entries)
    source_entries = [
        (object_id, item.content_sha256)
        for object_id, (contract_type, item) in closure.items()
        if contract_type == "SourceDocument"
    ]
    status, missing_evidence = _bundle_status(references)
    lock_hash = file_sha256(base_graph.component_lock_path)
    payload = {
        "schema_version": "1.0.0",
        "bundle_id": bundle_identifier(
            manifest.issuer_id,
            manifest.data_cutoff_date,
            dependency_hash,
        ),
        "issuer_id": manifest.issuer_id,
        "data_cutoff_date": manifest.data_cutoff_date,
        "bundle_policy_id": BUNDLE_POLICY_ID,
        "bundle_policy_version": BUNDLE_POLICY_VERSION,
        "status": status,
        "module_references": references,
        "source_document_ids": sorted(
            object_id
            for object_id, (contract_type, _) in closure.items()
            if contract_type == "SourceDocument"
        ),
        "fiscal_period_ids": sorted(
            object_id
            for object_id, (contract_type, _) in closure.items()
            if contract_type == "FiscalPeriod"
        ),
        "segment_definition_ids": sorted(
            object_id
            for object_id, (contract_type, _) in closure.items()
            if contract_type == "SegmentDefinition"
        ),
        "source_graph_sha256": source_graph_sha256(source_entries),
        "dependency_closure_sha256": dependency_hash,
        "component_lock_sha256": lock_hash,
        "bundle_fingerprint": "0" * 64,
        "run_id": run_id,
        "missing_evidence": missing_evidence,
    }
    payload["bundle_fingerprint"] = bundle_payload_sha256(payload)
    bundle = contract_from_dict("research-bundle", payload)
    if not isinstance(bundle, ResearchBundle):
        raise ResearchBundleBuildError("ResearchBundle contract construction failed")

    updated_manifests, updated_manifest = _replace_manifest_output(
        base_graph.manifests,
        run_id=run_id,
        bundle_fingerprint=bundle.bundle_fingerprint,
    )
    final_graph = replace(
        base_graph,
        manifests=updated_manifests,
        research_bundles=(bundle,),
    )
    try:
        final_graph.validate()
    except ContractGraphError as exc:
        raise ResearchBundleBuildError(f"Constructed ResearchBundle is invalid: {exc}") from exc

    existing = [item for item in graph.research_bundles if item.run_id == run_id]
    if existing and any(item != bundle for item in existing):
        raise ResearchBundleBuildError("Existing ResearchBundle is stale or conflicts with replay")
    return ResearchBundleBuildResult(bundle=bundle, run_manifest=updated_manifest)
