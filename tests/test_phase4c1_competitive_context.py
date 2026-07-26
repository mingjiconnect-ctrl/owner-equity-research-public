from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest
from phase4a_support import valid_phase4a_graph

from owner_research.competitive_context import (
    CompetitiveContextError,
    ContextCoverageInput,
    ContextSourceClient,
    build_competitive_context_snapshot,
    build_confirmed_context_observation,
    build_context_source_document,
    validate_context_url,
)
from owner_research.sec import ContentAddressedCache
from owner_research.validation import CONTEXT_TOPICS, ContractGraph

SCOPE = {
    "scope_type": "issuer_wide",
    "segment_definition_ids": [],
    "business_unit": None,
    "product_service": None,
    "geography": None,
    "customer_group": None,
    "channel": None,
}


def _competitor_evidence(tmp_path: Path, *, authority: str = "company_primary"):
    raw = b"Competitor serves the same customers through a substitute product."
    document = build_context_source_document(
        subject_entity_id="issuer:competitor",
        document_id="doc:competitor:official",
        document_type="official_ir",
        period={"start": "2025-01-01", "end": "2025-12-31"},
        published_date="2026-02-15",
        retrieved_at="2026-02-16T01:00:00Z",
        source_url="https://ir.competitor.example/evidence",
        authority_level=authority,
        raw=raw,
        allowed_hosts=frozenset({"competitor.example"}),
    )
    observation = build_confirmed_context_observation(
        raw=raw,
        source_document=document,
        target_issuer_id="issuer:acme",
        subject={
            "entity_id": "issuer:competitor",
            "entity_name": "Competitor",
            "role": "competitor",
        },
        as_of_date="2026-02-16",
        scope=SCOPE,
        observation_type="competitor_behavior",
        start=0,
        end=len(raw),
        extraction_method="manual",
        reviewer_id="reviewer:phase4c",
        reviewed_at="2026-02-16T03:00:00Z",
        confidence="medium",
    )
    return document, observation


def test_context_client_requires_identity_allowlist_https_and_bounded_rate(
    tmp_path: Path,
) -> None:
    with pytest.raises(CompetitiveContextError, match="allowlist"):
        ContextSourceClient(allowed_hosts=frozenset(), user_agent="research@example.com")
    with pytest.raises(CompetitiveContextError, match="User-Agent"):
        ContextSourceClient(allowed_hosts=frozenset({"example.com"}), user_agent="")
    with pytest.raises(CompetitiveContextError, match="at most 10"):
        ContextSourceClient(
            allowed_hosts=frozenset({"example.com"}),
            user_agent="research@example.com",
            requests_per_second=11,
        )
    with pytest.raises(CompetitiveContextError, match="HTTPS"):
        validate_context_url("http://example.com/evidence", frozenset({"example.com"}))
    with pytest.raises(CompetitiveContextError, match="governed SEC client"):
        validate_context_url("https://www.sec.gov/Archives/test", frozenset({"sec.gov"}))


def test_context_client_uses_external_content_addressed_cache(tmp_path: Path) -> None:
    raw = b"official context evidence"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["user-agent"] == "research@example.com"
        return httpx.Response(200, content=raw, request=request)

    cache = ContentAddressedCache(tmp_path / "external-cache")
    with ContextSourceClient(
        allowed_hosts=frozenset({"example.com"}),
        user_agent="research@example.com",
        requests_per_second=10,
        cache=cache,
        transport=httpx.MockTransport(handler),
    ) as client:
        assert client.get_bytes("https://example.com/evidence") == raw
    digest = hashlib.sha256(raw).hexdigest()
    assert (cache.root / digest[:2] / digest).read_bytes() == raw


def test_context_client_revalidates_redirect_hosts(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://unapproved.example/evidence"},
            request=request,
        )

    with ContextSourceClient(
        allowed_hosts=frozenset({"approved.example"}),
        user_agent="research@example.com",
        requests_per_second=10,
        cache=ContentAddressedCache(tmp_path / "cache"),
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CompetitiveContextError, match="allowlist"):
            client.get_bytes("https://approved.example/evidence")


def test_confirmed_observation_requires_exact_hash_subject_cutoff_and_human_work(
    tmp_path: Path,
) -> None:
    document, _ = _competitor_evidence(tmp_path)
    raw = b"Competitor serves the same customers through a substitute product."
    common = dict(
        raw=raw,
        source_document=document,
        target_issuer_id="issuer:acme",
        subject={
            "entity_id": "issuer:competitor",
            "entity_name": "Competitor",
            "role": "competitor",
        },
        as_of_date="2026-02-16",
        scope=SCOPE,
        observation_type="competitor_behavior",
        start=0,
        end=len(raw),
        reviewer_id="reviewer:phase4c",
        reviewed_at="2026-02-16T03:00:00Z",
        confidence="medium",
    )
    with pytest.raises(CompetitiveContextError, match="language-model"):
        build_confirmed_context_observation(**common, extraction_method="language_model")
    with pytest.raises(CompetitiveContextError, match="hash mismatch"):
        build_confirmed_context_observation(
            **{**common, "raw": b"changed"}, extraction_method="manual"
        )
    with pytest.raises(CompetitiveContextError, match="subject"):
        build_confirmed_context_observation(
            **{
                **common,
                "subject": {
                    "entity_id": "issuer:other",
                    "entity_name": "Other",
                    "role": "competitor",
                },
            },
            extraction_method="manual",
        )
    with pytest.raises(CompetitiveContextError, match="cutoff"):
        build_confirmed_context_observation(
            **{**common, "as_of_date": "2026-02-14"}, extraction_method="manual"
        )


def test_builder_produces_complete_context_with_target_and_independent_sources(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    competitor_document, competitor_observation = _competitor_evidence(tmp_path)
    observations = (graph.context_observations[0], competitor_observation)
    inputs = {
        topic: ContextCoverageInput(
            reviewed_observation_ids=(
                competitor_observation.observation_id
                if topic not in {"product_service", "customer_group"}
                else graph.context_observations[0].observation_id,
            )
        )
        for topic in CONTEXT_TOPICS
    }
    snapshot = build_competitive_context_snapshot(
        issuer_id="issuer:acme",
        as_of_date="2026-02-16",
        scope=SCOPE,
        source_documents=(*graph.documents, competitor_document),
        observations=observations,
        competitor_selection_claim_ids=(graph.claims[0].claim_id,),
        topic_inputs=inputs,
    )
    assert snapshot.status == "complete"
    ContractGraph(
        documents=(*graph.documents, competitor_document),
        facts=graph.facts,
        claims=graph.claims,
        context_observations=observations,
        competitive_context_snapshots=(snapshot,),
        analytical_claim_candidates=graph.analytical_claim_candidates,
        analytical_claim_review_decisions=graph.analytical_claim_review_decisions,
    ).validate()


def test_builder_fails_closed_without_competitor_selection_or_critical_scope(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    snapshot = build_competitive_context_snapshot(
        issuer_id="issuer:acme",
        as_of_date="2026-02-16",
        scope=SCOPE,
        source_documents=graph.documents,
        observations=graph.context_observations,
        competitor_selection_claim_ids=(),
        topic_inputs={
            "product_service": ContextCoverageInput(
                reviewed_observation_ids=(graph.context_observations[0].observation_id,)
            )
        },
    )
    assert snapshot.status == "blocked"
    assert "Competitor set lacks an analytical selection Claim" in snapshot.missing_evidence


def test_secondary_source_cannot_complete_competitive_context(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    document, observation = _competitor_evidence(tmp_path, authority="secondary")
    inputs = {
        topic: ContextCoverageInput(reviewed_observation_ids=(observation.observation_id,))
        for topic in CONTEXT_TOPICS
    }
    snapshot = build_competitive_context_snapshot(
        issuer_id="issuer:acme",
        as_of_date="2026-02-16",
        scope=SCOPE,
        source_documents=(*graph.documents, document),
        observations=(observation,),
        competitor_selection_claim_ids=(graph.claims[0].claim_id,),
        topic_inputs=inputs,
    )
    assert snapshot.status == "partial"
    assert any("source diversity" in item for item in snapshot.missing_evidence)


def test_builder_rejects_unknown_topics_and_mixed_review_states(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    common = dict(
        issuer_id="issuer:acme",
        as_of_date="2026-02-16",
        scope=SCOPE,
        source_documents=graph.documents,
        observations=graph.context_observations,
        competitor_selection_claim_ids=(graph.claims[0].claim_id,),
    )
    with pytest.raises(CompetitiveContextError, match="unknown"):
        build_competitive_context_snapshot(
            **common,
            topic_inputs={"sic_peer_set": ContextCoverageInput()},
        )
    with pytest.raises(CompetitiveContextError, match="reviewed and not-applicable"):
        build_competitive_context_snapshot(
            **common,
            topic_inputs={
                "product_service": ContextCoverageInput(
                    reviewed_observation_ids=(graph.context_observations[0].observation_id,),
                    not_applicable_claim_ids=(graph.claims[0].claim_id,),
                )
            },
        )
