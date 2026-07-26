from __future__ import annotations

import inspect
from dataclasses import replace

import pytest
from phase4a_support import replace_graph
from test_phase4e0_research_bundle import _bundle_graph, _replace_bundle

from owner_research.research_bundle_builder import (
    ResearchBundleBuildError,
    ResearchBundleBuildResult,
    build_research_bundle,
)
from owner_research.validation import ContractGraph


def _input_graph(sample_payloads) -> ContractGraph:
    graph, _ = _bundle_graph(sample_payloads)
    manifest = replace(graph.manifests[0], output_artifact_hashes={})
    return replace_graph(graph, manifests=(manifest,), research_bundles=())


def _completed_graph(graph: ContractGraph, result: ResearchBundleBuildResult) -> ContractGraph:
    manifests = tuple(
        result.run_manifest if item.run_id == result.run_manifest.run_id else item
        for item in graph.manifests
    )
    return replace_graph(
        graph,
        manifests=manifests,
        research_bundles=(result.bundle,),
    )


def test_builder_constructs_and_validates_bundle_with_atomic_manifest_binding(
    sample_payloads,
) -> None:
    graph = _input_graph(sample_payloads)
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)

    assert isinstance(result, ResearchBundleBuildResult)
    assert result.bundle.status == "blocked"
    assert (
        result.run_manifest.output_artifact_hashes["research-bundle.json"]
        == result.bundle.bundle_fingerprint
    )
    assert not graph.manifests[0].output_artifact_hashes
    _completed_graph(graph, result).validate()


def test_builder_is_idempotent_for_clean_and_completed_graphs(sample_payloads) -> None:
    graph = _input_graph(sample_payloads)
    first = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    second = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    replay = build_research_bundle(
        _completed_graph(graph, first),
        run_id=graph.manifests[0].run_id,
    )

    assert first == second == replay


def test_builder_output_is_independent_of_graph_collection_order(sample_payloads) -> None:
    graph = _input_graph(sample_payloads)
    baseline = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    reordered = replace_graph(
        graph,
        facts=tuple(reversed(graph.facts)),
        claims=tuple(reversed(graph.claims)),
        source_search_receipts=tuple(reversed(graph.source_search_receipts)),
        capital_allocation_events=tuple(reversed(graph.capital_allocation_events)),
    )
    result = build_research_bundle(reordered, run_id=reordered.manifests[0].run_id)

    assert result.bundle.bundle_id == baseline.bundle.bundle_id
    assert result.bundle.bundle_fingerprint == baseline.bundle.bundle_fingerprint
    assert result.run_manifest == baseline.run_manifest


def test_builder_fails_closed_on_equal_latest_module(sample_payloads) -> None:
    graph = _input_graph(sample_payloads)
    duplicate = replace(
        graph.management_reviews[0],
        review_id="management-review:acme:equal-latest",
    )
    ambiguous = replace_graph(
        graph,
        management_reviews=(*graph.management_reviews, duplicate),
    )
    result = build_research_bundle(ambiguous, run_id=ambiguous.manifests[0].run_id)
    reference = next(
        item
        for item in result.bundle.module_references
        if item["module_type"] == "management_review"
    )

    assert result.bundle.status == "blocked"
    assert reference["module_status"] == "blocked"
    assert not reference["object_ids"]
    assert "ambiguous" in " ".join(reference["missing_evidence"])
    _completed_graph(ambiguous, result).validate()


def test_builder_preserves_existing_manifest_outputs_and_updates_only_selected_run(
    sample_payloads,
) -> None:
    graph = _input_graph(sample_payloads)
    primary = replace(
        graph.manifests[0],
        output_artifact_hashes={"research-package.json": "7" * 64},
    )
    secondary = replace(
        primary,
        run_id="run:acme:secondary",
        output_artifact_hashes={"other.json": "6" * 64},
    )
    multi_run = replace_graph(graph, manifests=(primary, secondary))
    result = build_research_bundle(multi_run, run_id=primary.run_id)

    assert result.run_manifest.output_artifact_hashes["research-package.json"] == "7" * 64
    assert result.run_manifest.output_artifact_hashes["research-bundle.json"] == (
        result.bundle.bundle_fingerprint
    )
    assert secondary.output_artifact_hashes == {"other.json": "6" * 64}


def test_builder_rejects_missing_manifest_invalid_graph_and_conflicting_replay(
    sample_payloads,
) -> None:
    graph = _input_graph(sample_payloads)
    with pytest.raises(ResearchBundleBuildError, match="exactly one RunManifest"):
        build_research_bundle(graph, run_id="run:missing")

    broken_fact = replace(graph.facts[0], source_document_id="doc:missing")
    with pytest.raises(ResearchBundleBuildError, match="Input ContractGraph is invalid"):
        build_research_bundle(
            replace_graph(graph, facts=(broken_fact, *graph.facts[1:])),
            run_id=graph.manifests[0].run_id,
        )

    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, result)
    conflicting = _replace_bundle(
        completed,
        result.bundle,
        missing_evidence=[*result.bundle.missing_evidence, "Caller-authored gap"],
    )
    with pytest.raises(ResearchBundleBuildError, match="stale or conflicts"):
        build_research_bundle(conflicting, run_id=result.bundle.run_id)


def test_builder_api_accepts_no_caller_module_status_scope_or_hash_controls() -> None:
    signature = inspect.signature(build_research_bundle)
    assert tuple(signature.parameters) == ("graph", "run_id")
    assert signature.parameters["run_id"].kind is inspect.Parameter.KEYWORD_ONLY


def test_builder_does_not_add_cli_shadow_valuation_or_publisher_surface() -> None:
    import owner_research

    assert owner_research.build_research_bundle is build_research_bundle
    for forbidden in (
        "build_valuation_handoff",
        "publish_research_bundle",
        "run_research_bundle_shadow",
        "score_research_bundle",
    ):
        assert not hasattr(owner_research, forbidden)
