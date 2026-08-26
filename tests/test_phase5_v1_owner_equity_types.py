from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace

import pytest
from phase4a_support import replace_graph
from phase4e2_support import complete_phase4e_graph
from test_phase4e1_research_bundle_builder import _completed_graph, _input_graph
from test_phase5_v1_futu_data_plane import (
    RUN_ID,
    FakeTransport,
    _authorities,
    _live_decision,
    _pre_price_specs,
    _security_receipt,
)

from owner_research.fingerprints import FrozenMap, canonical_sha256, to_json_value
from owner_research.futu_receipts import (
    FutuAuthoritySet,
    FutuObservation,
    SignatureVerifier,
    content_identity,
)
from owner_research.futu_session import FutuMarketExecutionEvidence, FutuPeerEvidenceSet
from owner_research.futu_sidecar import FutuRequestSpec, execute_futu_plan
from owner_research.owner_equity_types import (
    FutuOptionalDataDisposition,
    FutuOptionalDataDispositionPublicationManifest,
    MarketExpectationsPublicationManifest,
    OwnerEquityTypeError,
    ResearchSourceIndex,
    RuntimeGapPublicationManifest,
    RuntimeGapReceipt,
    build_futu_optional_data_disposition_publication_manifests,
    build_futu_optional_data_dispositions,
    build_research_source_index,
    build_research_source_index_publication_manifest,
    build_runtime_gap_publication_manifest,
)
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.research_bundle_validation import dependency_closure
from owner_research.valuation_run import ValuationRunResult
from owner_research.valuation_synthesis_types import (
    CompositeValuationResult,
    ExtensionAuthorityError,
    ForwardReOIValuationResult,
    NamedHumanReviewAuthority,
    OwnerScorecard,
    ScoreV2,
    build_named_human_review_authority,
    retained_authority_replay_scope,
)


def _optional_review(sample_payloads):
    graph = _input_graph(sample_payloads)
    research = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, research)
    roots = tuple(
        object_id
        for reference in research.bundle.module_references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(completed, roots)
    object_type, fact = next(
        (object_type, item)
        for object_type, item in closure.values()
        if object_type == "Fact"
    )
    values = {
        "graph": completed,
        "research_bundle": research.bundle,
        "reviewer_id": "human:futu-data-reviewer",
        "reviewed_at": "2026-08-15T00:58:00Z",
        "rationale": "Freeze optional vendor context before any Futu request.",
        "reviewed_payload": {
            "company_executives": False,
            "executive_background_leader_name": None,
            "operational_efficiency": True,
            "us_buybacks_disposition": "not_supported_for_us_sec_primary",
        },
        "evidence_bindings": (
            {
                "object_type": object_type,
                "object_id": fact.fact_id,
                "fingerprint": fact.fingerprint,
            },
        ),
    }
    return values


def _financial_field_admission_payload() -> dict[str, object]:
    return {
        "registry_id": "futu-reviewed-financial-field-admission",
        "registry_version": "1.0.0",
        "futu_api_version": "10.10.7008",
        "market": "US",
        "mappings": [
            {
                "accounting_standard_scope": "US_GAAP",
                "canonical_concept": "cash_and_cash_equivalents",
                "display_name": "Synthetic Balance Item",
                "field_id": "900001",
                "source_raw_plaintext_sha256": "a" * 64,
                "statement_type": "balance_sheet",
            }
        ],
    }


def test_optional_no_data_marker_yields_unavailable_disposition(
    sample_payloads,
) -> None:
    review_values = _optional_review(sample_payloads)
    review = build_named_human_review_authority(
        scope="futu_optional_data_plan",
        **review_values,
    )
    authorities, _default_security, supply = _authorities(
        target_vendor_code="US.ACME",
        request_plan_profile="pre_price",
    )
    security = _security_receipt(
        issuer_id=review.issuer_id,
        security_id="security:ACME:XNAS:common",
        ticker="ACME",
    )
    authorities = FutuAuthoritySet(
        legal=authorities.legal,
        account=authorities.account,
        supply_chain=authorities.supply_chain,
        runtime_authorization=authorities.runtime_authorization,
        runtime=authorities.runtime,
        security_identity=security,
    )
    specs = (
        *_pre_price_specs(),
        FutuRequestSpec(
            "valuation_pre_price_verification",
            3246,
            FrozenMap({"currency_code": "USD", "num": 50}),
        ),
    )
    decision = _live_decision(
        authorities,
        protocols=tuple(item.protocol_id for item in specs),
    )
    assert authorities.runtime_authorization is not None
    execution = execute_futu_plan(
        transport=FakeTransport(),
        authority=decision,
        runtime_authorization=authorities.runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=review.issuer_id,
        security_id=security.security_id,
        stage="valuation_pre_price_verification",
        data_cutoff_date=review.data_cutoff_date,
        request_started_at="2026-08-15T01:00:00Z",
        specs=specs,
    )
    dispositions = build_futu_optional_data_dispositions(
        execution=execution,
        review_authority=review,
    )
    manifests = build_futu_optional_data_disposition_publication_manifests(
        dispositions
    )

    assert tuple(item.protocol_id for item in dispositions) == (3235, 3244, 3245, 3246)
    assert tuple(item.status for item in dispositions) == (
        "not_supported_for_us_sec_primary",
        "not_requested",
        "not_requested",
        "unavailable",
    )
    assert dispositions[-1].to_dict()["reason_code"] == (
        "vendor_returned_no_observations"
    )
    assert tuple(
        FutuOptionalDataDispositionPublicationManifest.from_dict(item.to_dict())
        for item in manifests
    ) == manifests


def test_named_human_review_still_rejects_unknown_scope(sample_payloads) -> None:
    with pytest.raises(ExtensionAuthorityError, match="invalid"):
        build_named_human_review_authority(
            scope="caller_defined_vendor_plan",
            **_optional_review(sample_payloads),
        )


def test_reviewed_financial_admission_is_bound_into_named_human_review_identity(
    sample_payloads,
) -> None:
    values = _optional_review(sample_payloads)
    values["reviewed_payload"]["financial_field_admission"] = _financial_field_admission_payload()
    review = build_named_human_review_authority(
        scope="futu_optional_data_plan",
        **values,
    )
    tampered_payload = to_json_value(review.reviewed_payload)
    assert isinstance(tampered_payload, dict)
    admission = dict(tampered_payload["financial_field_admission"])
    admission["market"] = "HK"
    tampered_payload["financial_field_admission"] = admission
    with pytest.raises(ExtensionAuthorityError, match="identity is not deterministic"):
        NamedHumanReviewAuthority(
            schema_version=review.schema_version,
            review_id=review.review_id,
            scope=review.scope,
            issuer_id=review.issuer_id,
            data_cutoff_date=review.data_cutoff_date,
            reviewer_id=review.reviewer_id,
            reviewed_at=review.reviewed_at,
            rationale=review.rationale,
            graph=review.graph,
            research_bundle=review.research_bundle,
            reviewed_payload=tampered_payload,
            evidence_bindings=review.evidence_bindings,
            review_fingerprint=review.review_fingerprint,
        )


def test_source_index_replays_exact_graph_bundle_and_public_projection(sample_payloads) -> None:
    graph = _input_graph(sample_payloads)
    research = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, research)

    index = build_research_source_index(graph=completed, research=research)
    publication = build_research_source_index_publication_manifest(index)

    assert index.to_dict() == publication.to_dict()
    assert index.fingerprint == publication.fingerprint
    assert index.to_dict()["research_bundle_fingerprint"] == research.bundle.bundle_fingerprint
    assert index.to_dict()["source_count"] == len(research.bundle.source_document_ids)
    assert all(item["source_url"].startswith("https://") for item in index.to_dict()["sources"])


def test_source_index_retains_bundle_scoped_independent_context_source(sample_payloads) -> None:
    graph = complete_phase4e_graph(sample_payloads)
    research = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, research)

    index = build_research_source_index(graph=completed, research=research)
    sources = {item["document_id"]: item for item in index.to_dict()["sources"]}

    assert research.bundle.status == "complete"
    assert sources["doc:industry:2025"]["source_issuer_id"] == "issuer:industry"
    assert sources["doc:industry:2025"]["source_scope"] == "external_context"
    assert sources[completed.documents[0].document_id]["source_scope"] == "target_issuer"


@dataclass(frozen=True, slots=True)
class PartialRuntimeFixture:
    run_result: ValuationRunResult
    forward_reoi: ForwardReOIValuationResult
    composite: CompositeValuationResult
    scores: tuple[ScoreV2, ...]
    scorecard: OwnerScorecard
    market_execution_evidence: FutuMarketExecutionEvidence
    peer_evidence_set: FutuPeerEvidenceSet
    optional_data_dispositions: tuple[FutuOptionalDataDisposition, ...]
    gap: RuntimeGapReceipt
    verifier: SignatureVerifier


@retained_authority_replay_scope
def build_partial_runtime_fixture(sample_payloads, monkeypatch, tmp_path):
    from test_phase5_v1_futu_data_plane import (
        _completed_runtime_receipt,
        build_complete_futu_session_fixture,
        build_futu_attested_finalization_fixture,
    )
    from test_phase5_v1_valuation_synthesis import (
        _complete_synthesis,
    )

    from owner_research.futu_receipts import build_futu_frozen_conclusion_receipt
    from owner_research.owner_scorecard import (
        build_owner_scorecard,
        build_score_v2,
        resolve_score_review_authority,
    )
    from owner_research.valuation_synthesis import build_composite_valuation

    (
        run_result,
        basis,
        forward,
        _peer_authority,
        _comparables,
        complete_composite,
        complete_scores,
        complete_scorecard,
    ) = _complete_synthesis(sample_payloads, monkeypatch, tmp_path)
    futu = build_complete_futu_session_fixture(
        run_result.input_receipt.expected_freeze,
        composite_valuation=complete_composite,
        owner_scorecard=complete_scorecard,
    )
    composite = build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=forward,
        comparables=None,
    )
    scores = tuple(
        build_score_v2(
            composite_valuation=composite,
            review_authority=resolve_score_review_authority(
                composite_valuation=composite,
                planned_review=complete_score._review_authority,
            ),
        )
        for complete_score in complete_scores
    )
    scorecard = build_owner_scorecard(
        composite_valuation=composite,
        lens_scores=scores,
    )
    assert all(score.status == "partial" and score.total_score is None for score in scores)
    assert scorecard.overall_score is None
    conclusion = build_futu_frozen_conclusion_receipt(
        run_id=RUN_ID,
        security_id=futu.live_authority_set.security_identity.security_id,
        composite_valuation=composite,
        owner_scorecard=scorecard,
        conclusion_frozen_at="2026-08-15T01:08:00Z",
    )
    executions = (
        *futu.market_execution_evidence.executions,
        *(item.execution for item in futu.peer_evidence_set.peers),
    )
    responses = tuple(
        response for execution in executions for response in execution.responses
    )
    runtime_receipt = _completed_runtime_receipt(
        futu.live_authority_set,
        responses=responses,
        ended_at="2026-08-15T01:09:00Z",
    )
    finalization = build_futu_attested_finalization_fixture(
        executions=executions,
        runtime_receipt=runtime_receipt,
        supply_chain=futu.live_authority_set.supply_chain,
        runtime_authorization=futu.live_authority_set.runtime_authorization,
        verifier=futu.verifier,
        skipped_conditional_conclusion=conclusion,
    )
    gap = RuntimeGapReceipt.create(
        phase="futu_market_expectations",
        composite_valuation=composite,
        owner_scorecard=scorecard,
        frozen_conclusion=conclusion,
        attested_finalization=finalization,
        issue_codes=("post_context_suppressed:conclusion_not_eligible",),
    )
    dispositions = build_futu_optional_data_dispositions(
        execution=futu.pre_execution,
        review_authority=futu.optional_data_review,
    )
    return PartialRuntimeFixture(
        run_result=run_result,
        forward_reoi=forward,
        composite=composite,
        scores=scores,
        scorecard=scorecard,
        market_execution_evidence=futu.market_execution_evidence,
        peer_evidence_set=futu.peer_evidence_set,
        optional_data_dispositions=dispositions,
        gap=gap,
        verifier=futu.verifier,
    )


def test_runtime_gap_derives_closed_public_projection(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    fixture = build_partial_runtime_fixture(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    publication = build_runtime_gap_publication_manifest(fixture.gap)

    assert RuntimeGapPublicationManifest.from_dict(publication.to_dict()) == publication
    assert publication.source_receipt_fingerprint == fixture.gap.fingerprint


def test_runtime_gap_publication_rejects_stale_upstream_hash(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    fixture = build_partial_runtime_fixture(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    payload = build_runtime_gap_publication_manifest(fixture.gap).to_dict()
    payload["upstream_fingerprints"]["composite_valuation"] = "b" * 64

    with pytest.raises(OwnerEquityTypeError, match="fingerprint"):
        RuntimeGapPublicationManifest.from_dict(payload)


def test_source_index_rejects_coordinated_document_rebind(sample_payloads) -> None:
    graph = _input_graph(sample_payloads)
    research = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, research)
    index = build_research_source_index(graph=completed, research=research)
    document = completed.documents[0]
    rebound_document = replace(
        document,
        source_url="https://www.sec.gov/Archives/edgar/data/rebound/filing.html",
    )
    rebound_graph = replace_graph(
        completed,
        documents=(rebound_document, *completed.documents[1:]),
    )

    with pytest.raises((OwnerEquityTypeError, ValueError)):
        ResearchSourceIndex.from_dict(
            index.to_dict(),
            graph=rebound_graph,
            research=research,
        )


@pytest.mark.parametrize(
    "source_url",
    (
        "https://www.sec.gov/Archives/filing.htm?token=secret",
        "https://user:password@www.sec.gov/Archives/filing.htm",
        "https://www.sec.gov/Archives/filing.htm#private",
    ),
)
def test_source_index_rejects_publishable_url_credentials(sample_payloads, source_url) -> None:
    sample_payloads["source-document"]["source_url"] = source_url
    graph = _input_graph(sample_payloads)
    research = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, research)

    with pytest.raises(OwnerEquityTypeError, match="URL"):
        build_research_source_index(graph=completed, research=research)


@pytest.mark.parametrize(
    "source_locator",
    (
        "/Users/reviewer/private/filing.txt",
        "table:1?api_key=secret",
        "https://user:password@example.com/filing",
    ),
)
def test_source_index_rejects_publishable_locator_secrets(
    sample_payloads, source_locator
) -> None:
    sample_payloads["fact"]["source_locator"] = source_locator
    graph = _input_graph(sample_payloads)
    research = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, research)

    with pytest.raises(OwnerEquityTypeError, match="locator"):
        build_research_source_index(graph=completed, research=research)


def _expectation_observation(data_family: str, field_id: str) -> FutuObservation:
    values = {
        "schema_version": "1.0.0",
        "issuer_id": "issuer:us:test",
        "security_id": "security:TEST:XNAS:common",
        "data_family": data_family,
        "field_id": field_id,
        "canonical_concept": f"vendor_{field_id}",
        "period": FrozenMap({"start": None, "end": "2026-08-14"}),
        "qualifiers": FrozenMap({}),
        "value_type": "number",
        "value": "100",
        "unit": "ratio",
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
        "response_fingerprint": "a" * 64,
        "retrieved_at": "2026-08-15T01:00:00Z",
        "point_in_time_status": "current_snapshot",
        "source_role": "vendor_secondary",
        "use_scope": "post_valuation_context",
        "comparison_eligible": True,
    }
    observation_id, fingerprint = content_identity(
        "futu-observation:",
        values,
        object_id_field="observation_id",
        fingerprint_field="observation_fingerprint",
    )
    return FutuObservation(
        observation_id=observation_id,
        observation_fingerprint=fingerprint,
        **values,
    )


def _unavailable_expectation_observation(data_family: str) -> FutuObservation:
    values = {
        "schema_version": "1.0.0",
        "issuer_id": "issuer:us:test",
        "security_id": "security:TEST:XNAS:common",
        "data_family": data_family,
        "field_id": "availability",
        "canonical_concept": None,
        "period": FrozenMap({"start": None, "end": None}),
        "qualifiers": FrozenMap(
            {
                "availability_status": "unavailable",
                "reason_code": "official_no_data",
            }
        ),
        "value_type": "null",
        "value": None,
        "unit": None,
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
        "response_fingerprint": "a" * 64,
        "retrieved_at": "2026-08-15T01:00:00Z",
        "point_in_time_status": "current_snapshot",
        "source_role": "vendor_secondary",
        "use_scope": "post_valuation_context",
        "comparison_eligible": False,
    }
    observation_id, fingerprint = content_identity(
        "futu-observation:",
        values,
        object_id_field="observation_id",
        fingerprint_field="observation_fingerprint",
    )
    return FutuObservation(
        observation_id=observation_id,
        observation_fingerprint=fingerprint,
        **values,
    )


def test_post_context_all_unavailable_is_partial_not_complete() -> None:
    import owner_research.owner_equity_types as owner_types

    observations = tuple(
        _unavailable_expectation_observation(family)
        for family in (
            "analyst_consensus",
            "analyst_ratings",
            "valuation_context",
        )
    )
    execution = SimpleNamespace(
        bundle=SimpleNamespace(stage="post_valuation_context"),
        responses=(SimpleNamespace(fingerprint="a" * 64),),
        observations=observations,
    )
    retained = owner_types._expectation_observations(
        SimpleNamespace(executions=(execution,))
    )
    status, issue_codes = owner_types._expectation_coverage(retained)

    assert retained == ()
    assert status == "partial"
    assert issue_codes == (
        "market_expectations_missing:analyst_consensus",
        "market_expectations_missing:analyst_ratings",
        "market_expectations_missing:valuation_context",
    )


def _comparison_payload() -> dict[str, object]:
    observations = [
        _expectation_observation("analyst_consensus", "target_price").to_dict(),
        _expectation_observation("analyst_ratings", "rating_summary").to_dict(),
        _expectation_observation("valuation_context", "forward_pe").to_dict(),
    ]
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "market-expectations-comparison",
        "status": "complete",
        "issuer_id": "issuer:us:test",
        "as_of_date": "2026-08-14",
        "futu_session_id": "futu-session:" + "b" * 64,
        "futu_session_fingerprint": "b" * 64,
        "composite_valuation_fingerprint": "c" * 64,
        "owner_scorecard_fingerprint": "d" * 64,
        "frozen_conclusion_receipt": {
            "object_id": "futu-conclusion-freeze:" + "e" * 64,
            "fingerprint": "e" * 64,
        },
        "post_valuation_execution": {
            "object_id": "futu-bundle:" + "f" * 64,
            "fingerprint": "f" * 64,
        },
        "post_requests": [
            {
                "object_id": "futu-request:" + "1" * 64,
                "fingerprint": "1" * 64,
            }
        ],
        "post_responses": [
            {
                "object_id": "futu-response:" + "a" * 64,
                "fingerprint": "a" * 64,
            }
        ],
        "frozen_conclusion": {
            "composite_status": "complete",
            "current_intrinsic_value": "120",
            "twelve_month_target": "130",
            "recommendation": "关注",
            "recommendation_eligible": True,
        },
        "observations": observations,
        "issue_codes": [],
        "influence_attestation": "post_conclusion_context_only_no_model_or_score_input",
    }
    payload["comparison_id"] = (
        f"market-expectations-comparison:issuer:us:test:{canonical_sha256(payload)[:24]}"
    )
    payload["comparison_fingerprint"] = canonical_sha256(payload)
    return payload


def test_market_expectations_publication_replays_each_observation_value() -> None:
    manifest = MarketExpectationsPublicationManifest.from_dict(_comparison_payload())
    payload = manifest.to_dict()
    payload["observations"][0]["value"] = "999"
    payload.pop("comparison_id")
    payload.pop("comparison_fingerprint")
    payload["comparison_id"] = (
        f"market-expectations-comparison:issuer:us:test:{canonical_sha256(payload)[:24]}"
    )
    payload["comparison_fingerprint"] = canonical_sha256(payload)

    with pytest.raises(OwnerEquityTypeError, match="observations do not replay"):
        MarketExpectationsPublicationManifest.from_dict(payload)


def test_market_expectations_publication_rejects_rebound_post_response() -> None:
    payload = _comparison_payload()
    payload["post_responses"] = [
        {
            "object_id": "futu-response:" + "9" * 64,
            "fingerprint": "9" * 64,
        }
    ]
    payload.pop("comparison_id")
    payload.pop("comparison_fingerprint")
    payload["comparison_id"] = (
        f"market-expectations-comparison:issuer:us:test:{canonical_sha256(payload)[:24]}"
    )
    payload["comparison_fingerprint"] = canonical_sha256(payload)

    with pytest.raises(OwnerEquityTypeError, match="post-execution references"):
        MarketExpectationsPublicationManifest.from_dict(payload)
