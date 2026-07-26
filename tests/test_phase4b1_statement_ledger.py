from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.management_sources import (
    OfficialSourceClient,
    OfficialSourceError,
    build_official_source_document,
    select_management_filings,
)
from owner_research.management_statements import (
    StatementLedgerError,
    build_statement_candidate,
    normalized_source_text,
    review_statement_candidate,
)
from owner_research.sec import ContentAddressedCache
from owner_research.validation import ContractGraph, ContractGraphError

RAW = b"<html><body><p>We expect revenue growth of 5% to 7% in fiscal 2026.</p></body></html>"
TEXT = "We expect revenue growth of 5% to 7% in fiscal 2026."


def _source(authority: str = "company_primary"):
    return build_official_source_document(
        issuer_id="issuer:acme",
        document_id="doc:acme:official-guidance",
        document_type="earnings-release",
        period={"start": "2026-01-01", "end": "2026-12-31"},
        published_date="2026-02-15",
        retrieved_at="2026-02-16T01:00:00Z",
        source_url="https://ir.acme.example/guidance",
        authority_level=authority,
        raw=RAW,
        allowed_hosts=frozenset({"acme.example"}),
    )


def _mentions() -> tuple[dict[str, object], ...]:
    common = {
        "component_id": "primary",
        "metric_concept": "revenue_growth",
        "value_type": "number",
        "unit": "ratio",
        "currency": None,
        "period": {"start": "2026-01-01", "end": "2026-12-31"},
        "scope": {
            "scope_type": "issuer",
            "scope_id": "issuer:acme",
            "scope_label": "Acme consolidated",
        },
        "measurement_basis": {
            "accounting_basis": "gaap",
            "currency_basis": "reported",
            "growth_basis": "reported",
            "aggregation_basis": "period",
        },
    }
    return (
        {**common, "role": "lower_bound", "value": 0.05},
        {**common, "role": "upper_bound", "value": 0.07},
    )


def test_language_model_candidate_requires_human_decision() -> None:
    source = _source()
    text = normalized_source_text(RAW)
    candidate = build_statement_candidate(
        raw=RAW,
        source_document=source,
        start=0,
        end=len(text),
        speaker_name="Alex Executive",
        speaker_role="Chief Executive Officer",
        statement_date="2026-02-15",
        statement_type="guidance",
        kpi_concept=None,
        extraction_method="language_model",
        metric_mentions=_mentions(),
    )
    confirmation = review_statement_candidate(
        candidate,
        source_document=source,
        decision="confirmed",
        reviewer_id="reviewer:human",
        reviewed_at="2026-02-16T02:00:00Z",
        rationale="Checked every metric against the exact company-hosted span.",
    )
    assert confirmation.statement is not None
    assert confirmation.statement.verification_status == "human_confirmed"
    assert len(confirmation.facts) == 2
    ContractGraph(
        documents=(source,),
        facts=confirmation.facts,
        management_statements=(confirmation.statement,),
        management_statement_candidates=(candidate,),
        management_statement_review_decisions=(confirmation.decision,),
    ).validate()


def test_confirmed_statement_without_decision_is_rejected(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    with pytest.raises(ContractGraphError, match="lacks a review decision"):
        replace_graph(graph, management_statement_review_decisions=()).validate()


def test_confirmed_target_fact_must_equal_candidate_metric() -> None:
    source = _source()
    candidate = build_statement_candidate(
        raw=RAW,
        source_document=source,
        start=0,
        end=len(normalized_source_text(RAW)),
        speaker_name="Alex Executive",
        speaker_role="Chief Executive Officer",
        statement_date="2026-02-15",
        statement_type="guidance",
        kpi_concept=None,
        extraction_method="manual",
        metric_mentions=_mentions(),
    )
    confirmation = review_statement_candidate(
        candidate,
        source_document=source,
        decision="confirmed",
        reviewer_id="reviewer:human",
        reviewed_at="2026-02-16T02:00:00Z",
        rationale="Checked the exact official span.",
    )
    forged = replace(confirmation.facts[0], value=0.50)
    with pytest.raises(ContractGraphError, match="differs from candidate metric mention"):
        ContractGraph(
            documents=(source,),
            facts=(forged, confirmation.facts[1]),
            management_statements=(confirmation.statement,),
            management_statement_candidates=(candidate,),
            management_statement_review_decisions=(confirmation.decision,),
        ).validate()


def test_blocked_candidate_cannot_be_confirmed() -> None:
    source = _source()
    candidate = build_statement_candidate(
        raw=RAW,
        source_document=source,
        start=0,
        end=len(normalized_source_text(RAW)),
        speaker_name="Alex Executive",
        speaker_role="Chief Executive Officer",
        statement_date="2026-02-15",
        statement_type="guidance",
        kpi_concept=None,
        extraction_method="language_model",
        metric_mentions=({**_mentions()[0], "currency": "USD"},),
    )
    assert candidate.validation_status == "blocked"
    with pytest.raises(StatementLedgerError, match="cannot be confirmed"):
        review_statement_candidate(
            candidate,
            source_document=source,
            decision="confirmed",
            reviewer_id="reviewer:human",
            reviewed_at="2026-02-16T02:00:00Z",
            rationale="Attempted confirmation.",
        )


def test_third_party_or_analyst_source_cannot_confirm_statement() -> None:
    source = _source()
    candidate = build_statement_candidate(
        raw=RAW,
        source_document=source,
        start=0,
        end=len(normalized_source_text(RAW)),
        speaker_name="Consensus",
        speaker_role="Analyst consensus",
        statement_date="2026-02-15",
        statement_type="other",
        kpi_concept=None,
        extraction_method="manual",
    )
    secondary = replace(source, authority_level="secondary")
    with pytest.raises(StatementLedgerError, match="official source"):
        review_statement_candidate(
            candidate,
            source_document=secondary,
            decision="confirmed",
            reviewer_id="reviewer:human",
            reviewed_at="2026-02-16T02:00:00Z",
            rationale="Analyst material is not management evidence.",
        )


def test_official_client_enforces_allowlist_and_final_redirect(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"official", request=request)

    cache = ContentAddressedCache(tmp_path / "cache")
    with OfficialSourceClient(
        allowed_hosts=frozenset({"acme.example"}),
        cache=cache,
        transport=httpx.MockTransport(handler),
    ) as client:
        assert client.get_bytes("https://ir.acme.example/release") == b"official"
        with pytest.raises(OfficialSourceError, match="allowlist"):
            client.get_bytes("https://third-party.example/transcript")

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "https://third-party.example/transcript"},
            request=request,
        )

    with OfficialSourceClient(
        allowed_hosts=frozenset({"acme.example"}),
        cache=cache,
        transport=httpx.MockTransport(redirect_handler),
    ) as client:
        with pytest.raises(OfficialSourceError, match="allowlist"):
            client.get_bytes("https://ir.acme.example/redirect")


def test_management_filing_selection_includes_governance_forms_before_cutoff() -> None:
    recent = {
        "accessionNumber": ["0000000001-26-000001", "0000000001-26-000002"],
        "form": ["8-K", "DEF 14A"],
        "filingDate": ["2026-02-01", "2026-08-01"],
        "reportDate": ["2026-02-01", "2026-08-01"],
        "primaryDocument": ["event.htm", "proxy.htm"],
    }
    selected = select_management_filings(
        {"filings": {"recent": recent}}, cik="1", cutoff_date="2026-07-11"
    )
    assert [item.form for item in selected] == ["8-K"]


def test_candidate_rejects_source_hash_or_span_mismatch() -> None:
    source = _source()
    with pytest.raises(StatementLedgerError, match="hash mismatch"):
        build_statement_candidate(
            raw=b"changed",
            source_document=source,
            start=0,
            end=1,
            speaker_name="Alex Executive",
            speaker_role="CEO",
            statement_date="2026-02-15",
            statement_type="guidance",
            kpi_concept=None,
            extraction_method="manual",
        )
