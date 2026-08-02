from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_phase5e2b12a_integration_contracts as fixtures
from phase4a_support import replace_graph

import owner_research.valuation_current_share_compiler as compiler
from owner_research.source_search_receipts import build_source_search_receipt
from owner_research.valuation_current_share_vertical import (
    _claim_transitions,
    _coverage_ledger,
)
from owner_research.valuation_share_event_integration_types import (
    COVERAGE_SEARCH_ENDPOINTS,
    COVERAGE_SEARCH_TOOL_VERSION,
    CurrentShareEvidenceClosureV2,
)


class _Artifact:
    fingerprint = "f" * 64

    def __init__(self, research_bundle_id: str) -> None:
        self.research_bundle_id = research_bundle_id

    def to_dict(self) -> dict[str, object]:
        return {
            "issuer_id": fixtures.ISSUER,
            "data_cutoff_date": fixtures.CUTOFF,
            "protected_mckinsey_sha256": "a" * 64,
            "protected_penman_assumptions_sha256": "b" * 64,
            "research_bundle": {"bundle_id": self.research_bundle_id},
        }


class _StandardAuthority:
    standard_path_disposition = "eligible"

    @classmethod
    def from_price_blind_artifact(cls, _artifact: object) -> _StandardAuthority:
        return cls()


def test_v2_coverage_trace_is_fail_closed_without_capturing_phase4_receipts(
    sample_payloads: dict[str, dict],
) -> None:
    _expected, graph = fixtures._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    kwargs = {
        "issuer_id": fixtures.ISSUER,
        "opening_date": fixtures.OPENING_DATE,
        "quote_date": fixtures.QUOTE_DATE,
        "data_cutoff_date": fixtures.CUTOFF,
    }

    assert compiler._v2_coverage_authority_state(graph, **kwargs) == "complete"

    first, *rest = graph.source_search_receipts
    drifted_tool = replace_graph(
        graph,
        source_search_receipts=(
            replace(first, tool_version="owner-research-current-share-coverage/9.9.9"),
            *rest,
        ),
    )
    assert compiler._v2_coverage_authority_state(drifted_tool, **kwargs) == "incomplete"

    drifted_endpoint = replace_graph(
        graph,
        source_search_receipts=(
            replace(first, searched_endpoints=("authority:wrong",)),
            *rest,
        ),
    )
    assert (
        compiler._v2_coverage_authority_state(drifted_endpoint, **kwargs)
        == "incomplete"
    )

    phase4_receipts = tuple(
        replace(
            item,
            tool_version="phase4d5-fixture/1.0.0",
            searched_endpoints=COVERAGE_SEARCH_ENDPOINTS[item.source_family],
        )
        for item in graph.source_search_receipts
    )
    phase4_graph = SimpleNamespace(source_search_receipts=phase4_receipts)
    assert compiler._v2_coverage_authority_state(phase4_graph, **kwargs) == "absent"

    assert all(
        item.tool_version == COVERAGE_SEARCH_TOOL_VERSION
        and item.searched_endpoints == COVERAGE_SEARCH_ENDPOINTS[item.source_family]
        for item in graph.source_search_receipts
    )


def test_v2_ledger_ignores_coexisting_phase4_receipts(
    sample_payloads: dict[str, dict],
) -> None:
    expected, graph = fixtures._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    documents = {item.document_id: item for item in graph.documents}
    phase4_receipts = tuple(
        build_source_search_receipt(
            issuer_id=item.issuer_id,
            source_family_id=item.source_family,
            query_scope=item.query_scope,
            period=item.period,
            cutoff_date=item.cutoff_date,
            searched_endpoints=item.searched_endpoints,
            result_documents=tuple(documents[value] for value in item.result_document_ids),
            completed_at=item.completed_at,
            tool_version="owner-research-source-search/1.0.0",
        )
        for item in graph.source_search_receipts
    )
    mixed = replace_graph(
        graph,
        source_search_receipts=(*graph.source_search_receipts, *phase4_receipts),
    )
    ledger = _coverage_ledger(
        graph=mixed,
        materializations=expected.materializations,
        issuer_id=fixtures.ISSUER,
        security_id=fixtures.SECURITY,
        opening_date=fixtures.OPENING_DATE,
        quote_date=fixtures.QUOTE_DATE,
        data_cutoff_date=fixtures.CUTOFF,
    )

    assert ledger == expected.coverage_ledger


def _compile_fixture_context(
    *,
    expected: CurrentShareEvidenceClosureV2,
    graph,
    monkeypatch: pytest.MonkeyPatch,
):
    security = expected.bundle_evidence_closure.security_compilation_result
    artifact = _Artifact(expected.bundle_evidence_closure.research_bundle_id)
    freeze = SimpleNamespace(
        artifact=artifact,
        handoffs=(SimpleNamespace(handoff_id="handoff:phase5-v1"),),
    )
    access = SimpleNamespace(
        status="eligible",
        request=SimpleNamespace(
            authorization_handoff_id="handoff:phase5-v1",
            security_id=fixtures.SECURITY,
        ),
        receipt=SimpleNamespace(
            security_compilation_fingerprint=security.fingerprint,
            receipt=SimpleNamespace(trading_date=fixtures.QUOTE_DATE),
        ),
        issuer_id=fixtures.ISSUER,
        data_cutoff_date=fixtures.CUTOFF,
        authorization_handoff_id="handoff:phase5-v1",
        price_blind_input_fingerprint=artifact.fingerprint,
        protected_mckinsey_sha256="a" * 64,
        protected_penman_assumptions_sha256="b" * 64,
    )
    monkeypatch.setattr(
        compiler,
        "load_price_blind_input_artifact",
        lambda *args, **kwargs: freeze,
    )
    monkeypatch.setattr(
        compiler,
        "compile_security_identity",
        lambda *args, **kwargs: security,
    )
    monkeypatch.setattr(compiler, "Phase5CDilutionClaimAuthority", _StandardAuthority)
    return compiler.compile_quote_date_current_common_shares(
        price_blind_artifact_directory=Path("/unused"),
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )


def test_reviewed_canonical_group_compiles_through_real_v2_closure(
    sample_payloads: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected, graph = fixtures._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    result = _compile_fixture_context(
        expected=expected,
        graph=graph,
        monkeypatch=monkeypatch,
    )

    assert result.status == "eligible"
    assert type(result.evidence_closure) is CurrentShareEvidenceClosureV2
    assert result.evidence_closure.to_dict() == expected.to_dict()
    assert result.output_fact == expected.output_share_fact
    assert result.output_fact.value == 95_000_000
    assert result.canonical_rollforward is not None
    assert len(result.canonical_rollforward.numeric_consumptions) == 1
    materialization = result.evidence_closure.materializations[0]
    assert len(materialization.members) == 2
    assert {item.fact_id for item in materialization.members} == {
        "fact:event:2026:0",
        "fact:event:2026:1",
    }
    assert len({item.source_document_id for item in materialization.members}) == 2
    assert all(item.candidates for item in materialization.members)
    assert all(item.review_decisions for item in materialization.members)
    observed_entry = next(
        item for item in expected.coverage_ledger.entries if item.status == "observed"
    )
    zero_template = next(
        item.zero_fact for item in expected.coverage_ledger.entries if item.zero_fact is not None
    )
    assert zero_template is not None
    contradictory_zero = replace(
        zero_template,
        fact_id=f"fact:coverage-zero:{observed_entry.category}:conflict",
        concept=f"share_activity_{observed_entry.category}_count",
    )
    conflict = _compile_fixture_context(
        expected=expected,
        graph=replace_graph(graph, facts=(*graph.facts, contradictory_zero)),
        monkeypatch=monkeypatch,
    )
    assert conflict.status == "blocked"
    assert conflict.output_fact is None
    assert conflict.evidence_closure is None

    unreviewed_event_fact = replace(
        materialization.members[0].fact,
        fact_id="fact:event:unreviewed-in-window",
        value=1_000_000,
        source_locator="fixture:event:unreviewed-in-window",
    )
    incomplete_grouping = _compile_fixture_context(
        expected=expected,
        graph=replace_graph(graph, facts=(*graph.facts, unreviewed_event_fact)),
        monkeypatch=monkeypatch,
    )
    assert incomplete_grouping.status == "blocked"
    assert incomplete_grouping.output_fact is None
    assert incomplete_grouping.evidence_closure is None


def test_v2_rollforward_preserves_integer_precision_above_decimal_context(
    sample_payloads: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opening_value = 123456789012345678901234567896
    expected_value = opening_value - 5_000_000
    expected, graph = fixtures._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
        opening_value=opening_value,
        output_value=expected_value,
    )

    result = _compile_fixture_context(
        expected=expected,
        graph=graph,
        monkeypatch=monkeypatch,
    )

    assert result.status == "eligible"
    assert result.output_fact is not None
    assert result.output_fact.value == expected_value
    assert result.evidence_closure is not None
    assert result.evidence_closure.output_share_fact.value == expected_value


def test_v2_closure_ignores_unrelated_filing_artifact(
    sample_payloads: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected, graph = fixtures._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    template = graph.filing_artifacts[0]
    unrelated = replace(
        template,
        artifact_id="filing:acme:unrelated-2025-10k",
        source_document_id="doc:acme:2025-10k",
        accession="0000000001-25-000099",
        form="10-K",
        filing_date="2026-02-15",
        report_period="2025-12-31",
    )
    same_source_unbound = replace(
        template,
        artifact_id="filing:acme:same-source-unbound",
        accession="0000000001-25-000098",
        raw_sha256="d" * 64,
        normalized_sha256="e" * 64,
        parser_version="unbound/9.9.9",
    )
    polluted = replace_graph(
        graph,
        filing_artifacts=(*graph.filing_artifacts, unrelated, same_source_unbound),
    )
    polluted.validate()

    result = _compile_fixture_context(
        expected=expected,
        graph=polluted,
        monkeypatch=monkeypatch,
    )

    assert result.status == "eligible"
    assert type(result.evidence_closure) is CurrentShareEvidenceClosureV2
    assert result.evidence_closure.to_dict() == expected.to_dict()


def test_v2_closure_blocks_two_exact_opening_filing_identities(
    sample_payloads: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected, graph = fixtures._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    template = graph.filing_artifacts[0]
    duplicate = replace(
        template,
        artifact_id="filing:acme:same-source-unbound",
        accession="0000000001-25-000098",
        normalized_sha256="d" * 64,
        parser_version="unbound/9.9.9",
    )
    polluted = replace_graph(
        graph,
        filing_artifacts=(*graph.filing_artifacts, duplicate),
    )

    polluted.validate()
    result = _compile_fixture_context(
        expected=expected,
        graph=polluted,
        monkeypatch=monkeypatch,
    )

    assert result.status == "blocked"
    assert result.output_fact is None


def test_zero_event_v2_compiles_with_all_search_and_category_closures(
    sample_payloads: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected, graph = fixtures._accepted_empty_context(
        sample_payloads=sample_payloads,
    )

    result = _compile_fixture_context(
        expected=expected,
        graph=graph,
        monkeypatch=monkeypatch,
    )

    assert result.status == "eligible"
    assert type(result.evidence_closure) is CurrentShareEvidenceClosureV2
    assert result.evidence_closure.to_dict() == expected.to_dict()
    assert result.output_fact == expected.output_share_fact
    assert result.output_fact.value == 100_000_000
    assert result.canonical_rollforward is not None
    assert result.canonical_rollforward.materializations == ()
    assert result.canonical_rollforward.numeric_consumptions == ()
    assert len(expected.coverage_ledger.receipts) == 8
    assert len(expected.coverage_ledger.entries) == 12
    assert all(
        item.status
        in {"official_zero_or_no_activity", "not_applicable_with_reviewed_proof"}
        for item in expected.coverage_ledger.entries
    )


def test_option_group_replays_one_graph_owned_reviewed_claim_transition(
    sample_payloads: dict[str, dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grouping_evidence = fixtures._grouping(concept="option_shares_exercised_completed")
    grouping, raw_facts, event_sources, candidates, decisions, event = grouping_evidence
    materialization = fixtures._materialization(
        grouping=grouping,
        raw_facts=raw_facts,
        event_sources=event_sources,
        event_candidates=candidates,
        event_decisions=decisions,
        capital_event=event,
    )
    root_source = fixtures._source(
        "phase5-v1-option-root",
        document_type="10-K",
        published_date=fixtures.OPENING_DATE,
    )
    root_seed = fixtures._fact(
        fact_id="fact:claim:phase5-v1-option-root",
        concept="option_or_dilution_claim",
        value=10_000_000,
        source=root_source,
        end=fixtures.OPENING_DATE,
    )
    authority, graph, _freeze = fixtures._claim_authority_context(
        sample_payloads,
        monkeypatch,
        root_seed,
    )
    affected_fact = next(item for item in graph.facts if item.fact_id == root_seed.fact_id)
    affected_source = next(
        item for item in graph.documents if item.document_id == affected_fact.source_document_id
    )
    economic_claim_key = dict(authority.root_economic_claim_bindings)[affected_fact.fact_id]
    expected = fixtures._claim_transition(
        materialization=materialization,
        affected_fact=affected_fact,
        affected_source=affected_source,
        remaining_fact_id="ignored:deterministic",
        economic_claim_key=economic_claim_key,
    )

    documents = {item.document_id: item for item in graph.documents}
    documents.update({item.document_id: item for item in event_sources})
    documents[expected.remaining_claim_source_document.document_id] = (
        expected.remaining_claim_source_document
    )
    facts = {item.fact_id: item for item in graph.facts}
    facts.update({item.fact_id: item for item in raw_facts})
    facts[materialization.canonical_event_fact_id] = materialization.canonical_event_fact
    facts[expected.remaining_claim_fact_id] = expected.remaining_claim_fact
    claims = {item.claim_id: item for item in graph.claims}
    claims.update({item.claim_id: item for item in expected.claims})
    analytical_candidates = {item.candidate_id: item for item in graph.analytical_claim_candidates}
    analytical_candidates.update({item.candidate_id: item for item in expected.candidates})
    analytical_decisions = {
        item.decision_id: item for item in graph.analytical_claim_review_decisions
    }
    analytical_decisions.update({item.decision_id: item for item in expected.review_decisions})
    graph = replace_graph(
        graph,
        documents=tuple(documents.values()),
        facts=tuple(facts.values()),
        claims=tuple(claims.values()),
        analytical_claim_candidates=tuple(analytical_candidates.values()),
        analytical_claim_review_decisions=tuple(analytical_decisions.values()),
    )

    actual = _claim_transitions(
        graph=graph,
        materializations=(materialization,),
        issuer_id=fixtures.ISSUER,
        security_id=fixtures.SECURITY,
        opening_date=fixtures.OPENING_DATE,
        quote_date=fixtures.QUOTE_DATE,
        data_cutoff_date=fixtures.CUTOFF,
        claim_control_authority=authority,
    )

    assert actual.records == (expected,)
    assert actual.claim_control_authority == authority
