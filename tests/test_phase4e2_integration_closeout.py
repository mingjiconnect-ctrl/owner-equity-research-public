from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from phase4e2_support import complete_phase4e_graph
from test_phase4e1_research_bundle_builder import _completed_graph, _input_graph

from owner_research.research_bundle_artifacts import (
    load_research_bundle_artifacts,
    write_research_bundle_artifacts,
)
from owner_research.research_bundle_builder import build_research_bundle

ROOT = Path(__file__).parents[1]


def _with_document(graph, document):
    manifest = graph.manifests[0]
    updated_manifest = replace(
        manifest,
        input_document_hashes={
            **dict(manifest.input_document_hashes),
            document.document_id: document.content_sha256,
        },
    )
    return replace(
        graph,
        documents=(*graph.documents, document),
        manifests=(updated_manifest,),
    )


def test_complete_bundle_materializes_and_replays_end_to_end(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph = complete_phase4e_graph(sample_payloads)
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)

    assert result.bundle.status == "complete"
    assert {
        (item["module_status"], item["freshness"]["status"])
        for item in result.bundle.module_references
    } == {("complete", "current")}

    output = tmp_path / "complete"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    loaded = load_research_bundle_artifacts(output, graph=graph)
    assert loaded == result
    _completed_graph(graph, loaded).validate()


def test_new_policy_source_makes_bundle_partial_without_old_module_fallback(
    sample_payloads,
) -> None:
    graph = complete_phase4e_graph(sample_payloads)
    newer_source = replace(
        graph.documents[0],
        document_id="doc:acme:2026-q1-10q",
        document_type="10-Q",
        period={"start": "2026-01-01", "end": "2026-03-31"},
        published_date="2026-04-30",
        source_url="https://www.sec.gov/Archives/acme-2026-q1",
        content_sha256="9" * 64,
    )
    stale_graph = _with_document(graph, newer_source)
    result = build_research_bundle(
        stale_graph,
        run_id=stale_graph.manifests[0].run_id,
    )

    assert result.bundle.status == "partial"
    quarterly = next(
        item
        for item in result.bundle.module_references
        if item["module_type"] == "quarterly_update"
    )
    assert quarterly["object_ids"] == (graph.quarterly_updates[0].update_id,)
    assert quarterly["freshness"]["status"] == "stale"
    assert newer_source.document_id in quarterly["freshness"][
        "qualifying_source_document_ids"
    ]


def test_missing_modules_remain_blocked_through_artifact_roundtrip(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph = _input_graph(sample_payloads)
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)

    assert result.bundle.status == "blocked"
    assert any(
        item["module_status"] == "blocked"
        for item in result.bundle.module_references
    )
    output = tmp_path / "blocked"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    loaded = load_research_bundle_artifacts(output, graph=graph)
    assert loaded.bundle.status == "blocked"
    _completed_graph(graph, loaded).validate()


def test_competitor_regulatory_source_cannot_stale_target_operating_modules(
    sample_payloads,
) -> None:
    graph = complete_phase4e_graph(sample_payloads)
    external = next(item for item in graph.documents if item.issuer_id != "issuer:acme")
    updated_external = replace(
        external,
        document_type="10-Q",
        published_date="2026-02-16",
        source_url="https://www.sec.gov/Archives/industry-2026-q1",
        content_sha256="b" * 64,
    )
    manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            item.document_id: (
                updated_external.content_sha256
                if item.document_id == updated_external.document_id
                else item.content_sha256
            )
            for item in graph.documents
        },
    )
    updated_graph = replace(
        graph,
        documents=tuple(
            updated_external if item.document_id == updated_external.document_id else item
            for item in graph.documents
        ),
        manifests=(manifest,),
    )
    result = build_research_bundle(
        updated_graph,
        run_id=manifest.run_id,
    )

    assert result.bundle.status == "complete"
    for reference in result.bundle.module_references:
        assert reference["freshness"]["status"] == "current"


def test_input_order_and_unrelated_history_do_not_change_bundle_fingerprint(
    sample_payloads,
) -> None:
    graph = complete_phase4e_graph(sample_payloads)
    baseline = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    reordered = replace(
        graph,
        documents=tuple(reversed(graph.documents)),
        facts=tuple(reversed(graph.facts)),
        claims=tuple(reversed(graph.claims)),
        footnote_reviews=tuple(reversed(graph.footnote_reviews)),
        analytical_claim_candidates=tuple(
            reversed(graph.analytical_claim_candidates)
        ),
        analytical_claim_review_decisions=tuple(
            reversed(graph.analytical_claim_review_decisions)
        ),
    )
    reordered_result = build_research_bundle(
        reordered,
        run_id=reordered.manifests[0].run_id,
    )
    assert reordered_result.bundle == baseline.bundle

    historical_source = replace(
        graph.documents[0],
        document_id="doc:acme:2024-10k-history",
        period={"start": "2024-01-01", "end": "2024-12-31"},
        published_date="2025-02-15",
        source_url="https://www.sec.gov/Archives/acme-2024",
        content_sha256="a" * 64,
    )
    historical_graph = _with_document(graph, historical_source)
    historical_result = build_research_bundle(
        historical_graph,
        run_id=historical_graph.manifests[0].run_id,
    )
    assert historical_result.bundle == baseline.bundle


def test_existing_company_shadows_are_not_fabricated_integration_graphs() -> None:
    shadow_root = ROOT / "evals" / "shadow" / "2026-07-11"
    paths = [
        shadow_root / "business-quality-amazon.json",
        shadow_root / "business-quality-salesforce.json",
        shadow_root / "business-quality-union-pacific.json",
    ]
    for path in paths:
        payload = json.loads(path.read_text("utf-8"))
        assert payload["shadow_type"] == "phase4c_business_quality"
        assert "module_references" not in payload
        assert "research-bundle.json" not in payload.get("run_manifest", {}).get(
            "output_artifact_hashes", {}
        )
    assert not list(shadow_root.glob("research-bundle*.json"))
