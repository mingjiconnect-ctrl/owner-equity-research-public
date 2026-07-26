from __future__ import annotations

from pathlib import Path

from phase4a_support import replace_graph
from phase5e2a_support import (
    PHASE5C_DILUTED_ROOT_ID,
    _rebind_freeze_to_phase5c_authority,
)
from test_phase5e1_market_access import _access, _clock, _security_context

from owner_research.contracts import Fact
from owner_research.valuation_market_adapters import RecordedMarketQuoteProvider
from owner_research.valuation_price_blind_freeze import write_price_blind_input_artifact
from owner_research.valuation_security_identity import compile_security_identity

ROOT = Path(__file__).parents[1]
RAW_FIXTURE = ROOT / "tests/fixtures/phase5e2a/recorded-official-close.json"


def current_share_compile_context(sample_payloads, monkeypatch, tmp_path: Path):
    graph, freeze, directory, security = _security_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    graph, freeze = _rebind_freeze_to_phase5c_authority(graph, freeze)
    security = compile_security_identity(
        graph=graph,
        expected_freeze=freeze,
        proposal=security.proposal,
    )
    write_price_blind_input_artifact(
        graph,
        freeze,
        output_directory=directory,
        overwrite=True,
    )
    graph = replace_graph(
        graph,
        valuation_handoffs=freeze.handoffs,
        component_lock_path=ROOT / "component-lock.json",
    )
    _clock(
        monkeypatch,
        ("2026-07-14T01:00:00+00:00", 100),
        ("2026-07-14T01:00:01+00:00", 101),
    )
    access = _access(
        directory,
        graph,
        freeze,
        security,
        RecordedMarketQuoteProvider(RAW_FIXTURE.read_bytes()),
    )
    assert access.status == "eligible" and access.receipt is not None
    formal_source = graph.documents[0]
    phase5c_shares = Fact(
        schema_version="2.0.0",
        fact_id=PHASE5C_DILUTED_ROOT_ID,
        issuer_id="issuer:acme",
        concept="diluted_shares",
        value_type="number",
        value=100_000_000,
        unit="shares",
        currency=None,
        period={"start": None, "end": "2025-12-31"},
        source_document_id=formal_source.document_id,
        source_locator="phase5c:reviewed-diluted-shares",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    current_shares = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:current-common-shares:2026-06-30",
        issuer_id="issuer:acme",
        concept="common_shares_outstanding",
        value_type="number",
        value=100_000_000,
        unit="shares",
        currency=None,
        period={"start": None, "end": access.receipt.receipt.trading_date},
        source_document_id=formal_source.document_id,
        source_locator="share-basis:quote-date:current-common-shares",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = replace_graph(
        graph,
        facts=graph.facts + (phase5c_shares, current_shares),
    )
    return graph, freeze, directory, security, access, current_shares

