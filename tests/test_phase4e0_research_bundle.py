from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from jsonschema import ValidationError
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.component_lock import file_sha256
from owner_research.contracts import ResearchBundle, contract_from_dict
from owner_research.research_bundle_policies import (
    MODULE_TYPES,
    bundle_identifier,
    bundle_payload_sha256,
    dependency_closure_sha256,
    module_artifact_sha256,
    source_graph_sha256,
)
from owner_research.research_bundle_validation import (
    _as_of,
    _expected_freshness,
    _issuer_scope,
    _period_for,
    _scope_payload,
    _status_for,
    dependency_closure,
)
from owner_research.schema_store import validate_payload
from owner_research.validation import ContractGraphError

ROOT = Path(__file__).parents[1]


def _bundle_graph(sample_payloads: dict[str, dict]):
    graph = valid_phase4a_graph(sample_payloads)
    cutoff = "2026-06-30"
    periods = {item.period_id: item for item in graph.periods}
    selected = {
        "quarterly_update": [],
        "segment_snapshot": [graph.segment_snapshots[0]],
        "footnote_review": [],
        "accounting_quality_review": [],
        "management_review": [graph.management_reviews[0]],
        "business_quality_review": [graph.business_quality_reviews[0]],
        "capital_allocation_review": [graph.capital_allocation_reviews[0]],
    }
    material_scope = graph.business_model_snapshots[0].material_scopes[0]
    references = []
    roots: list[str] = []
    missing: set[str] = set()
    bundle_status = "complete"
    for module_type in MODULE_TYPES:
        objects = selected[module_type]
        object_ids = []
        for item in objects:
            for attribute in ("update_id", "snapshot_id", "review_id"):
                if hasattr(item, attribute):
                    object_ids.append(getattr(item, attribute))
                    break
        roots.extend(object_ids)
        module_status = _status_for(module_type, objects)
        freshness = _expected_freshness(graph, module_type, objects, periods, cutoff)
        module_missing = sorted(
            {
                *(issue for item in objects for issue in getattr(item, "missing_evidence", ())),
                *([] if objects else [f"{module_type} is unavailable"]),
            }
        )
        if module_status == "blocked" or freshness["status"] == "blocked":
            bundle_status = "blocked"
        elif bundle_status != "blocked" and (
            module_status == "partial" or freshness["status"] == "stale"
        ):
            bundle_status = "partial"
        missing.update(module_missing)
        missing.update(freshness["missing_evidence"])
        scope = (
            _scope_payload(material_scope)
            if module_type == "business_quality_review"
            else _issuer_scope("issuer:acme")
        )
        references.append(
            {
                "module_type": module_type,
                "object_ids": sorted(object_ids),
                "module_status": module_status,
                "as_of_date": (
                    max(_as_of(item, periods) for item in objects) if objects else cutoff
                ),
                "period": _period_for(objects[0], periods) if objects else None,
                "scope": scope,
                "freshness": freshness,
                "artifact_sha256": module_artifact_sha256(
                    [
                        (type(item).__name__, object_id, item.fingerprint)
                        for item, object_id in zip(objects, object_ids, strict=True)
                    ]
                ),
                "missing_evidence": module_missing,
            }
        )

    closure = dependency_closure(graph, tuple(roots))
    entries = [
        (contract_type, object_id, item.fingerprint)
        for object_id, (contract_type, item) in closure.items()
    ]
    dependency_hash = dependency_closure_sha256(entries)
    source_entries = [
        (object_id, item.content_sha256)
        for object_id, (contract_type, item) in closure.items()
        if contract_type == "SourceDocument"
    ]
    lock_hash = file_sha256(graph.component_lock_path)
    payload = {
        "schema_version": "1.0.0",
        "bundle_id": bundle_identifier("issuer:acme", cutoff, dependency_hash),
        "issuer_id": "issuer:acme",
        "data_cutoff_date": cutoff,
        "bundle_policy_id": "research-bundle",
        "bundle_policy_version": "1.0.0",
        "status": bundle_status,
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
        "run_id": "run:acme:phase4e0",
        "missing_evidence": sorted(missing),
    }
    payload["bundle_fingerprint"] = bundle_payload_sha256(payload)
    bundle = contract_from_dict("research-bundle", payload)
    manifest_payload = copy.deepcopy(sample_payloads["run-manifest"])
    manifest_payload.update(
        {
            "run_id": bundle.run_id,
            "data_cutoff_date": cutoff,
            "started_at": "2026-07-01T00:00:00Z",
            "completed_at": "2026-07-01T01:00:00Z",
            "component_lock_sha256": lock_hash,
            "component_versions": {"owner-equity-research": "0.4.0-alpha.1"},
            "input_document_hashes": {
                item.document_id: item.content_sha256 for item in graph.documents
            },
            "output_artifact_hashes": {"research-bundle.json": bundle.bundle_fingerprint},
        }
    )
    manifest = contract_from_dict("run-manifest", manifest_payload)
    return replace_graph(graph, manifests=(manifest,), research_bundles=(bundle,)), bundle


def _replace_bundle(graph, bundle, **updates):
    payload = bundle.to_dict()
    payload.update(updates)
    if "bundle_fingerprint" not in updates:
        payload["bundle_fingerprint"] = bundle_payload_sha256(payload)
    replacement = contract_from_dict("research-bundle", payload)
    manifest = graph.manifests[0]
    manifest = replace(
        manifest,
        output_artifact_hashes={"research-bundle.json": replacement.bundle_fingerprint},
    )
    return replace_graph(graph, manifests=(manifest,), research_bundles=(replacement,))


def test_research_bundle_schema_is_closed_immutable_and_stably_fingerprinted(
    sample_payloads,
) -> None:
    payload = sample_payloads["research-bundle"]
    bundle = contract_from_dict("research-bundle", payload)
    assert isinstance(bundle, ResearchBundle)
    assert bundle.fingerprint == bundle.bundle_fingerprint
    with pytest.raises(ValidationError):
        validate_payload("research-bundle", {**payload, "target_price": 100})
    with pytest.raises(FrozenInstanceError):
        bundle.status = "complete"


def test_synthetic_research_bundle_passes_full_contract_graph(sample_payloads) -> None:
    graph, _ = _bundle_graph(sample_payloads)
    graph.validate()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("issuer_id", "issuer:other", "multiple issuers|issuer"),
        (
            "data_cutoff_date",
            "2025-12-31",
            "current object|cutoff|future|freshness|material business scope",
        ),
        ("source_graph_sha256", "1" * 64, "source graph hash"),
        ("dependency_closure_sha256", "1" * 64, "identifier|dependency closure hash"),
        ("component_lock_sha256", "1" * 64, "component lock"),
        ("status", "partial", "status was forged"),
    ],
)
def test_bundle_rejects_identity_hash_lock_and_status_tampering(
    sample_payloads, field, value, message
) -> None:
    graph, bundle = _bundle_graph(sample_payloads)
    tampered = _replace_bundle(graph, bundle, **{field: value})
    with pytest.raises(ContractGraphError, match=message):
        tampered.validate()


def test_bundle_rejects_old_module_and_scope_substitution(sample_payloads) -> None:
    graph, bundle = _bundle_graph(sample_payloads)
    references = copy.deepcopy(bundle.to_dict()["module_references"])
    management = next(item for item in references if item["module_type"] == "management_review")
    management["object_ids"] = []
    management["module_status"] = "blocked"
    management["missing_evidence"] = ["Caller selected no current review"]
    management["artifact_sha256"] = module_artifact_sha256([])
    tampered = _replace_bundle(graph, bundle, module_references=references)
    with pytest.raises(ContractGraphError, match="current object"):
        tampered.validate()

    references = copy.deepcopy(bundle.to_dict()["module_references"])
    business = next(item for item in references if item["module_type"] == "business_quality_review")
    business["scope"] = _issuer_scope("issuer:acme")
    tampered = _replace_bundle(graph, bundle, module_references=references)
    with pytest.raises(ContractGraphError, match="scope"):
        tampered.validate()


def test_bundle_rejects_forged_freshness_and_module_artifact(sample_payloads) -> None:
    graph, bundle = _bundle_graph(sample_payloads)
    references = copy.deepcopy(bundle.to_dict()["module_references"])
    segment = next(item for item in references if item["module_type"] == "segment_snapshot")
    segment["freshness"] = {
        **dict(segment["freshness"]),
        "status": "stale",
        "missing_evidence": ["Caller forged stale state"],
    }
    tampered = _replace_bundle(graph, bundle, module_references=references)
    with pytest.raises(ContractGraphError, match="freshness"):
        tampered.validate()

    references = copy.deepcopy(bundle.to_dict()["module_references"])
    references[0]["artifact_sha256"] = "1" * 64
    tampered = _replace_bundle(graph, bundle, module_references=references)
    with pytest.raises(ContractGraphError, match="artifact hash"):
        tampered.validate()


def test_bundle_rejects_manifest_output_and_cutoff_mismatch(sample_payloads) -> None:
    graph, _ = _bundle_graph(sample_payloads)
    manifest = replace(graph.manifests[0], output_artifact_hashes={})
    with pytest.raises(ContractGraphError, match="output hash"):
        replace_graph(graph, manifests=(manifest,)).validate()

    manifest = replace(graph.manifests[0], data_cutoff_date="2026-06-29")
    with pytest.raises(ContractGraphError, match="identity mismatch"):
        replace_graph(graph, manifests=(manifest,)).validate()


def test_unrelated_history_does_not_change_bundle_fingerprint(sample_payloads) -> None:
    graph, bundle = _bundle_graph(sample_payloads)
    historical = replace(
        graph.documents[0],
        document_id="doc:acme:history",
        period={"start": "2020-01-01", "end": "2020-12-31"},
        published_date="2021-02-01",
        content_sha256="9" * 64,
    )
    manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            **dict(graph.manifests[0].input_document_hashes),
            historical.document_id: historical.content_sha256,
        },
    )
    extended = replace_graph(graph, documents=(*graph.documents, historical), manifests=(manifest,))
    extended.validate()
    assert extended.research_bundles[0].bundle_fingerprint == bundle.bundle_fingerprint


def test_bundle_rejects_forbidden_assumption_dependency(sample_payloads) -> None:
    graph, _ = _bundle_graph(sample_payloads)
    assumption = contract_from_dict("assumption", sample_payloads["assumption"])
    calculation = contract_from_dict("calculation-result", sample_payloads["calculation-result"])
    management = replace(
        graph.management_reviews[0], calculation_result_ids=(calculation.calculation_id,)
    )
    with pytest.raises(ContractGraphError, match="Assumption|input_fingerprint"):
        replace_graph(
            graph,
            assumptions=(assumption,),
            calculations=(calculation,),
            management_reviews=(management,),
        ).validate()


def test_bundle_serialization_is_order_independent(sample_payloads) -> None:
    graph, bundle = _bundle_graph(sample_payloads)
    payload = bundle.to_dict()
    payload["module_references"] = list(reversed(payload["module_references"]))
    payload["bundle_fingerprint"] = bundle_payload_sha256(payload)
    reordered_bundle = contract_from_dict("research-bundle", payload)
    assert reordered_bundle.bundle_fingerprint == bundle.bundle_fingerprint
    assert graph.research_bundles[0].bundle_fingerprint == bundle.bundle_fingerprint


def test_equal_latest_modules_fail_closed_instead_of_id_tiebreak(sample_payloads) -> None:
    graph, _ = _bundle_graph(sample_payloads)
    duplicate = replace(graph.management_reviews[0], review_id="management-review:acme:tie")
    with pytest.raises(ContractGraphError, match="Ambiguous current management_review"):
        replace_graph(
            graph,
            management_reviews=(*graph.management_reviews, duplicate),
        ).validate()


def test_new_policy_relevant_source_invalidates_stale_freshness(sample_payloads) -> None:
    graph, _ = _bundle_graph(sample_payloads)
    newer = replace(
        graph.documents[0],
        document_id="doc:acme:2026-10q",
        document_type="10-Q",
        period={"start": "2026-01-01", "end": "2026-03-31"},
        published_date="2026-06-01",
        content_sha256="8" * 64,
    )
    manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            **dict(graph.manifests[0].input_document_hashes),
            newer.document_id: newer.content_sha256,
        },
    )
    with pytest.raises(ContractGraphError, match="freshness"):
        replace_graph(
            graph,
            documents=(*graph.documents, newer),
            manifests=(manifest,),
        ).validate()


def test_analytical_claim_cannot_enter_bundle_without_human_decision(sample_payloads) -> None:
    graph, _ = _bundle_graph(sample_payloads)
    with pytest.raises(ContractGraphError, match="review|Decision|dangling"):
        replace_graph(graph, analytical_claim_review_decisions=()).validate()


def test_phase4e1_exports_only_bundle_builder_without_later_phase_surfaces() -> None:
    package = ROOT / "src" / "owner_research"
    forbidden_files = {
        "research_bundle_cli.py",
        "research_bundle_orchestrator.py",
        "research_bundle_shadow.py",
    }
    assert not forbidden_files.intersection(path.name for path in package.glob("*.py"))
    public_text = (package / "__init__.py").read_text(encoding="utf-8")
    assert "build_research_bundle" in public_text
    schema_text = (ROOT / "schemas" / "research-bundle.schema.json").read_text(encoding="utf-8")
    for forbidden in (
        "score",
        "assumption",
        "market_price",
        "target_price",
        "recommendation",
        "publisher",
        "valuation",
    ):
        assert f'"{forbidden}"' not in schema_text.lower()
