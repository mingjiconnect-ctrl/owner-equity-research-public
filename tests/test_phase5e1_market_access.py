from __future__ import annotations

import inspect
import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime
from pathlib import Path

import pytest
from phase4a_support import replace_graph
from test_phase5d5_price_blind_freeze import _compile

import owner_research
import owner_research.valuation_market_access as market_access
from owner_research.analytical_claims import review_analytical_claim_candidate
from owner_research.contracts import AnalyticalClaimCandidate, Fact
from owner_research.fingerprints import canonical_sha256
from owner_research.valuation_market_access import acquire_governed_market_quote
from owner_research.valuation_market_adapters import RecordedMarketQuoteProvider
from owner_research.valuation_market_authority import load_market_access_authority
from owner_research.valuation_market_calendar import select_latest_completed_session
from owner_research.valuation_price_blind_freeze import write_price_blind_input_artifact
from owner_research.valuation_security_identity import (
    SecurityAccessProposal,
    SecurityFactBinding,
    compile_security_identity,
)

ROOT = Path(__file__).parents[1]


def _security_context(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
    *,
    structure: str = "single_primary_common",
):
    graph, freeze = _compile(sample_payloads, monkeypatch)
    document = graph.documents[0]
    cutoff = freeze.artifact.to_dict()["data_cutoff_date"]
    values = {
        "ticker": ("security_ticker", "ACME"),
        "mic": ("security_mic", "XNYS"),
        "share_class": ("security_share_class", "common"),
        "security_structure": ("security_structure", structure),
    }
    facts = tuple(
        Fact(
            schema_version="2.0.0",
            fact_id=f"fact:acme:security:{role}",
            issuer_id="issuer:acme",
            concept=concept,
            value_type="text",
            value=value,
            unit=None,
            currency=None,
            period={"start": None, "end": cutoff},
            source_document_id=document.document_id,
            source_locator=f"cover:{role}",
            derivation=None,
            parent_fact_ids=(),
            confidence="high",
        )
        for role, (concept, value) in values.items()
    )
    supporting = tuple(
        {
            "binding_id": f"security-binding:{index}",
            "fact_id": fact.fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for index, fact in enumerate(facts, start=1)
    )
    evidence_hash = canonical_sha256(
        {
            "supporting_evidence_bindings": supporting,
            "counterevidence_bindings": (),
        }
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id="analytical-candidate:acme:security-structure",
        issuer_id="issuer:acme",
        as_of_date=cutoff,
        proposed_statement="ACME has one primary listed common-share security for this route.",
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        counterevidence_search_note=(
            "Reviewed the cover, security notes, exchange identity, ADR disclosures, "
            "cross-listings, and multiple-class disclosures."
        ),
        proposed_confidence="high",
        falsification_condition=(
            "A formal filing identifies an ADR, a second price-forming class, a cross-listing, "
            "or another primary security."
        ),
        generation_method="manual",
        evidence_graph_sha256=evidence_hash,
        validation_status="ready",
        validation_issues=(),
    )
    claim, review = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:mingji",
        reviewed_at="2026-02-16T12:00:00Z",
        rationale="The formal security evidence and counterevidence search are complete.",
    )
    assert claim is not None
    graph = replace_graph(
        graph,
        facts=graph.facts + facts,
        claims=graph.claims + (claim,),
        analytical_claim_candidates=graph.analytical_claim_candidates + (candidate,),
        analytical_claim_review_decisions=graph.analytical_claim_review_decisions + (review,),
    )
    proposal = SecurityAccessProposal(
        proposal_id=f"security-proposal:acme:{cutoff}",
        issuer_id="issuer:acme",
        data_cutoff_date=cutoff,
        fact_bindings=tuple(
            SecurityFactBinding(role=role, fact_id=f"fact:acme:security:{role}")
            for role in values
        ),
        structure_claim_id=claim.claim_id,
        analytical_candidate_id=candidate.candidate_id,
        analytical_review_decision_id=review.decision_id,
    )
    security = compile_security_identity(
        graph=graph,
        expected_freeze=freeze,
        proposal=proposal,
    )
    directory = tmp_path / "price-blind"
    write_price_blind_input_artifact(graph, freeze, output_directory=directory)
    return graph, freeze, directory, security


def _raw_quote(security, *, observed_at: str = "2026-07-14T01:00:00Z", **changes: str) -> bytes:
    assert security.decision is not None
    authority = load_market_access_authority()
    selection = select_latest_completed_session(
        authority,
        mic=security.decision.exchange,
        cutoff_date=datetime.fromisoformat(security.proposal.data_cutoff_date).date(),
        observed_at=datetime.fromisoformat(observed_at.replace("Z", "+00:00")),
    )
    payload = {
        "security_id": security.decision.security_id,
        "ticker": security.decision.ticker,
        "exchange": security.decision.exchange,
        "share_class": security.decision.share_class,
        "trading_calendar_id": selection.calendar_id,
        "trading_date": selection.session.trading_date,
        "quote_timestamp": selection.session.closed_at,
        "session_kind": "regular",
        "session_status": "completed",
        "instrument_status": "active",
        "price_basis": "official_unadjusted_close",
        "quote_price": "50.125",
        "quote_currency": security.decision.quote_currency,
    }
    payload.update(changes)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _clock(monkeypatch, *values: tuple[str, int]) -> None:
    readings = iter(
        market_access._ClockReading(datetime.fromisoformat(stamp), monotonic)
        for stamp, monotonic in values
    )
    monkeypatch.setattr(market_access, "_clock_reading", lambda: next(readings))


def _access(directory, graph, freeze, security, provider):
    return acquire_governed_market_quote(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        provider=provider,
    )


def test_governed_access_is_internal_keyword_only_and_owns_all_authorities() -> None:
    signature = inspect.signature(acquire_governed_market_quote)
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert tuple(signature.parameters) == (
        "price_blind_artifact_directory",
        "graph",
        "expected_freeze",
        "expected_security",
        "provider",
    )
    for forbidden in (
        "provider_registry",
        "trading_calendar",
        "security_decision",
        "request_started_at",
        "retrieved_at",
    ):
        assert forbidden not in signature.parameters
    assert not hasattr(owner_research, "acquire_governed_market_quote")


def test_valid_recorded_quote_is_called_once_and_returns_governed_receipt(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    provider = RecordedMarketQuoteProvider(_raw_quote(security))
    _clock(
        monkeypatch,
        ("2026-07-14T01:00:00+00:00", 100),
        ("2026-07-14T01:00:01+00:00", 200),
    )
    result = _access(directory, graph, freeze, security, provider)
    assert result.status == "eligible"
    assert result.provider_call_count == 1 == provider.calls
    assert result.receipt is not None
    assert result.receipt.receipt.quote_price == "50.125"
    assert result.receipt.receipt.endpoint == "endpoint:recorded-official-close-v1"
    assert result.receipt.evidence_mode == "recorded_fixture"
    assert result.receipt.raw_response_sha256 == result.receipt.receipt.raw_response_sha256
    assert result.quarantined_raw_response_sha256 is None
    serialized = json.dumps(result.to_dict())
    assert '"raw_response"' not in serialized
    assert "50.125" in serialized
    with pytest.raises(FrozenInstanceError):
        result.status = "blocked"  # type: ignore[misc]


def test_unsupported_security_never_calls_provider(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
        structure="dual_or_multi_class_different_prices",
    )
    provider = RecordedMarketQuoteProvider(b"{}")
    result = _access(directory, graph, freeze, security, provider)
    assert result.status == "specialist_required"
    assert result.provider_call_count == 0 == provider.calls
    assert "dual_class_security_unsupported" in result.issue_codes


def test_forged_security_result_is_replayed_and_rejected(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    assert security.decision is not None
    forged = replace(security, decision=replace(security.decision, ticker="FORGED"))
    provider = RecordedMarketQuoteProvider(_raw_quote(security))
    result = _access(directory, graph, freeze, forged, provider)
    assert result.status == "blocked"
    assert result.issue_codes == ("security_identity_mismatch",)
    assert provider.calls == 0


def test_security_compiler_blocks_missing_future_and_unreviewed_evidence(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, _directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    missing = replace(
        security.proposal,
        fact_bindings=tuple(
            replace(item, fact_id="fact:missing")
            if item.role == "ticker"
            else item
            for item in security.proposal.fact_bindings
        ),
    )
    assert compile_security_identity(
        graph=graph,
        expected_freeze=freeze,
        proposal=missing,
    ).issue_codes == ("security_evidence_missing",)

    ticker_id = next(
        item.fact_id for item in security.proposal.fact_bindings if item.role == "ticker"
    )
    future_facts = tuple(
        replace(item, period={"start": None, "end": "2026-07-01"})
        if item.fact_id == ticker_id
        else item
        for item in graph.facts
    )
    future = compile_security_identity(
        graph=replace_graph(graph, facts=future_facts),
        expected_freeze=freeze,
        proposal=security.proposal,
    )
    assert future.issue_codes == ("security_evidence_future",)

    decision_id = security.proposal.analytical_review_decision_id
    unreviewed = tuple(
        replace(item, reviewer_id="llm:reviewer") if item.decision_id == decision_id else item
        for item in graph.analytical_claim_review_decisions
    )
    result = compile_security_identity(
        graph=replace_graph(graph, analytical_claim_review_decisions=unreviewed),
        expected_freeze=freeze,
        proposal=security.proposal,
    )
    assert result.issue_codes == ("security_claim_unreviewed",)


def test_old_component_lock_v4_context_requires_a_new_price_blind_run(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, _directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    old_lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    old_lock["lock_version"] = "1.0.0"
    old_lock.pop("market_access_authority")
    old_path = tmp_path / "old-component-lock.json"
    old_path.write_text(json.dumps(old_lock, sort_keys=True), encoding="utf-8")
    result = compile_security_identity(
        graph=replace(graph, component_lock_path=old_path),
        expected_freeze=freeze,
        proposal=security.proposal,
    )
    assert result.issue_codes == ("component_lock_mismatch",)


def test_tampered_artifact_blocks_before_provider(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    path = directory / "price-blind-input.json"
    path.write_bytes(path.read_bytes() + b"\n")
    provider = RecordedMarketQuoteProvider(_raw_quote(security))
    result = _access(directory, graph, freeze, security, provider)
    assert result.status == "blocked"
    assert result.issue_codes == ("artifact_reload_failed",)
    assert provider.calls == 0


def test_existing_downstream_handoff_prevents_second_access(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    later = replace(
        freeze.handoffs[-1],
        handoff_id=f"{freeze.handoffs[-1].handoff_id}:v5-test",
        handoff_version=5,
        state="request_compiled",
        predecessor_handoff_id=freeze.handoffs[-1].handoff_id,
        market_reference_snapshot_id="market-reference:test",
        valuation_request_sha256="a" * 64,
    )
    provider = RecordedMarketQuoteProvider(_raw_quote(security))
    graph = replace_graph(graph, valuation_handoffs=freeze.handoffs + (later,))
    result = _access(directory, graph, freeze, security, provider)
    assert result.status == "blocked"
    assert result.issue_codes == ("authorization_already_consumed",)
    assert provider.calls == 0


@pytest.mark.parametrize(
    "changes",
    (
        {"price_basis": "adjusted_close"},
        {"session_kind": "after_hours"},
        {"session_status": "in_progress"},
        {"instrument_status": "halted"},
        {"quote_currency": "EUR"},
        {"ticker": "OTHER"},
        {"quote_price": "NaN"},
        {"quote_price": "1e3"},
    ),
)
def test_invalid_raw_quote_is_hash_quarantined_not_promoted(
    sample_payloads, monkeypatch, tmp_path: Path, changes
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    provider = RecordedMarketQuoteProvider(_raw_quote(security, **changes))
    _clock(
        monkeypatch,
        ("2026-07-14T01:00:00+00:00", 100),
        ("2026-07-14T01:00:01+00:00", 200),
    )
    result = _access(directory, graph, freeze, security, provider)
    assert result.status == "blocked"
    assert result.provider_call_count == 1 == provider.calls
    assert result.receipt is None
    assert result.quarantined_raw_response_sha256 is not None
    assert result.issue_codes == ("provider_response_invalid",)


def test_provider_error_is_not_retried_and_has_no_fake_hash(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    provider = RecordedMarketQuoteProvider(b"{}", error=TimeoutError("fixture timeout"))
    _clock(
        monkeypatch,
        ("2026-07-14T01:00:00+00:00", 100),
        ("2026-07-14T01:00:01+00:00", 200),
    )
    result = _access(directory, graph, freeze, security, provider)
    assert result.status == "blocked"
    assert provider.calls == 1 == result.provider_call_count
    assert result.quarantined_raw_response_sha256 is None
    assert result.issue_codes == ("provider_call_failed",)


def test_caller_defined_provider_and_repository_subclass_are_rejected(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )

    class ForgedProvider(RecordedMarketQuoteProvider):
        pass

    provider = ForgedProvider(_raw_quote(security))
    result = _access(directory, graph, freeze, security, provider)
    assert result.status == "blocked"
    assert result.issue_codes == ("unregistered_provider",)
    assert provider.calls == 0

    exact = RecordedMarketQuoteProvider(_raw_quote(security))
    exact.request_official_close = lambda _request: None  # type: ignore[method-assign]
    rebound = _access(directory, graph, freeze, security, exact)
    assert rebound.issue_codes == ("unregistered_provider",)
    assert exact.calls == 0


def test_authorization_time_and_clock_regression_fail_closed(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    provider = RecordedMarketQuoteProvider(_raw_quote(security))
    _clock(monkeypatch, ("2026-02-16T23:59:59+00:00", 100))
    before = _access(directory, graph, freeze, security, provider)
    assert before.issue_codes == ("authorization_after_request_start",)
    assert provider.calls == 0

    provider = RecordedMarketQuoteProvider(_raw_quote(security))
    _clock(
        monkeypatch,
        ("2026-07-14T01:00:01+00:00", 200),
        ("2026-07-14T01:00:00+00:00", 100),
    )
    regressed = _access(directory, graph, freeze, security, provider)
    assert regressed.status == "blocked"
    assert regressed.receipt is None
    assert regressed.quarantined_raw_response_sha256 is not None
    assert regressed.issue_codes == ("clock_invalid",)


def test_same_recorded_bytes_and_times_replay_byte_stably(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, freeze, directory, security = _security_context(
        sample_payloads, monkeypatch, tmp_path
    )
    times = (
        ("2026-07-14T01:00:00+00:00", 100),
        ("2026-07-14T01:00:01+00:00", 200),
    )
    _clock(monkeypatch, *times)
    first = _access(
        directory,
        graph,
        freeze,
        security,
        RecordedMarketQuoteProvider(_raw_quote(security)),
    )
    _clock(monkeypatch, *times)
    second = _access(
        directory,
        graph,
        freeze,
        security,
        RecordedMarketQuoteProvider(_raw_quote(security)),
    )
    assert first == second
    assert first.fingerprint == second.fingerprint


def test_phase5e11_has_no_later_phase_or_implicit_surface() -> None:
    source = (ROOT / "src/owner_research/valuation_market_access.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "httpx",
        "requests",
        "urllib",
        "socket",
        "compile_final_valuation_request",
        "run_pinned_valuation_kernel",
        "write_valuation_artifacts",
    ):
        assert forbidden not in source
    assert not hasattr(owner_research, "MarketAccessResult")
