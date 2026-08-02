from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

from phase4a_support import replace_graph
from test_phase5e1_market_access import _access, _clock, _security_context

from owner_research.calculation_integrity import build_calculation_result
from owner_research.contracts import (
    CalculationResult,
    Fact,
    MarketReferenceSnapshot,
    SourceDocument,
)
from owner_research.fingerprints import canonical_sha256
from owner_research.validation import ContractGraph
from owner_research.valuation_current_share_compiler import (
    compile_quote_date_current_common_shares,
)
from owner_research.valuation_handoff_validation import (
    claim_control_fingerprint,
    future_request_v2_mapping_fingerprint,
    market_evidence_closure_sha256,
    parser_replay_fingerprint,
)
from owner_research.valuation_market_adapters import RecordedMarketQuoteProvider
from owner_research.valuation_market_reference_types import MarketReferenceValidationContext
from owner_research.valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindInputArtifact,
    write_price_blind_input_artifact,
)
from owner_research.valuation_security_identity import compile_security_identity

ROOT = Path(__file__).parents[1]
RAW_FIXTURE = ROOT / "tests/fixtures/phase5e2a/recorded-official-close.json"
RAW_LOCATOR = "repo://tests/fixtures/phase5e2a/recorded-official-close.json"
PHASE5C_DILUTED_ROOT_ID = "fact:acme:phase5c:diluted-shares:2025"
OPTION_ROOT_ID = "fact:acme:option-claim:2025"
OPTION_CLAIM_KEY = canonical_sha256(
    {
        "issuer_id": "issuer:acme",
        "identity_kind": "program",
        "identity_value": "fixture-option-program",
        "scope_id": "scope:issuer:acme:issuer-wide",
        "measurement_end": "2025-12-31",
        "security_class": "common",
    }
)


def _snapshot_fingerprint(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("snapshot_fingerprint", None)
    return canonical_sha256(unsigned)


def resign_snapshot(
    snapshot: MarketReferenceSnapshot,
    **changes: Any,
) -> MarketReferenceSnapshot:
    payload = snapshot.to_dict()
    payload.update(changes)
    if "quote_price_decimal" in changes and "numeric_evidence" not in changes:
        numeric = dict(payload["numeric_evidence"])
        numeric["authoritative_decimal"] = changes["quote_price_decimal"]
        payload["numeric_evidence"] = numeric
    payload["snapshot_fingerprint"] = _snapshot_fingerprint(payload)
    return MarketReferenceSnapshot(**payload)


def _phase5c_readiness_payload(*, issuer_id: str, cutoff: str) -> dict[str, Any]:
    option_binding = {
        "economic_identity": "option_or_dilution_claim",
        "economic_claim_key": OPTION_CLAIM_KEY,
        "root_fact_ids": [OPTION_ROOT_ID],
        "diluted_share_treatment": "excluded",
        "diluted_share_fact_ids": [PHASE5C_DILUTED_ROOT_ID],
    }
    bridge = {
        "issuer_id": issuer_id,
        "data_cutoff_date": cutoff,
        "status": "complete",
        "kernel_request_compatible": True,
        "diluted_shares_fact_id": PHASE5C_DILUTED_ROOT_ID,
        "diluted_share_root_fact_ids": [PHASE5C_DILUTED_ROOT_ID],
        "method_view_result": {
            "reconciliation_result": {"economic_claim_bindings": [option_binding]}
        },
        "role_decisions": [
            {
                "role": "option_or_dilution_claim",
                "status": "modeled",
                "root_fact_ids": [OPTION_ROOT_ID],
            }
        ],
        "consumption_records": [
            {
                "root_fact_id": OPTION_ROOT_ID,
                "economic_claim_key": OPTION_CLAIM_KEY,
                "economic_identity": "option_or_dilution_claim",
                "channel": "mckinsey_equity_bridge",
                "method": "mckinsey",
                "group_id": "equity-bridge:option_or_dilution_claim",
                "consumption_kind": "economic_deduction",
            }
        ],
    }
    return {
        "issuer_id": issuer_id,
        "data_cutoff_date": cutoff,
        "equity_bridge_fingerprint": canonical_sha256(bridge),
        "equity_bridge_result": bridge,
    }


def resign_price_blind_artifact(
    artifact: PriceBlindInputArtifact,
    phase5c_readiness: dict[str, Any],
) -> PriceBlindInputArtifact:
    payload = artifact.to_dict()
    payload["phase5c_readiness"] = phase5c_readiness
    payload["protected_mckinsey_sha256"] = canonical_sha256(
        {
            "fact_ledger": payload["reviewed_assumptions"]["augmented_fact_ledger_payload"],
            "assumption_ledger": payload["reviewed_assumptions"]["assumption_ledger_payload"],
            "phase5c_readiness": payload["phase5c_readiness"],
            "mckinsey_inputs": payload["mckinsey_inputs"],
        }
    )
    payload.pop("price_blind_input_fingerprint")
    payload["price_blind_input_fingerprint"] = canonical_sha256(payload)
    return PriceBlindInputArtifact(payload)


def _rebind_freeze_to_phase5c_authority(graph, freeze):
    source = freeze.artifact.to_dict()
    artifact = resign_price_blind_artifact(
        freeze.artifact,
        _phase5c_readiness_payload(
            issuer_id=source["issuer_id"],
            cutoff=source["data_cutoff_date"],
        ),
    )
    handoffs = tuple(
        replace(
            handoff,
            price_blind_input_fingerprint=artifact.fingerprint,
            protected_mckinsey_sha256=artifact.payload["protected_mckinsey_sha256"],
        )
        if handoff.state in {"price_blind_input_frozen", "market_reference_allowed"}
        else handoff
        for handoff in freeze.handoffs
    )
    rebound = PriceBlindFreezeCompilationResult(
        artifact=artifact,
        handoffs=handoffs,
        candidates=freeze.candidates,
        decisions=freeze.decisions,
        supplemental_reference_closure=freeze.supplemental_reference_closure,
    )
    return graph, rebound


def valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path: Path):
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
    assert access.status == "eligible"
    assert access.request is not None and access.receipt is not None
    assert security.decision is not None
    request = access.request
    governed = access.receipt
    receipt = governed.receipt
    source = SourceDocument(
        schema_version="1.0.0",
        document_id="doc:acme:market:2026-06-30",
        issuer_id="issuer:acme",
        document_type="market-quote",
        period={"start": None, "end": receipt.trading_date},
        published_date=receipt.trading_date,
        retrieved_at=receipt.retrieved_at,
        source_url="https://market.example.invalid/recorded/acme/2026-06-30",
        authority_level="market_reference",
        content_sha256=hashlib.sha256(RAW_FIXTURE.read_bytes()).hexdigest(),
    )
    quote_locator = f"market://{request.request_id}/{receipt.receipt_id}/{governed.parser_sha256}"
    quote = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:market-close:2026-06-30",
        issuer_id="issuer:acme",
        concept="market_quote_close",
        value_type="number",
        value=float(receipt.quote_price),
        unit="currency_per_share",
        currency=receipt.quote_currency,
        period={"start": None, "end": receipt.trading_date},
        source_document_id=source.document_id,
        source_locator=quote_locator,
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
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
    shares = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:current-common-shares:2026-06-30",
        issuer_id="issuer:acme",
        concept="common_shares_outstanding",
        value_type="number",
        value=100_000_000,
        unit="shares",
        currency=None,
        period={"start": None, "end": receipt.trading_date},
        source_document_id=formal_source.document_id,
        source_locator="share-basis:quote-date:current-common-shares",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    calculation_payload = {
        "schema_version": "2.0.0",
        "calculation_id": "calc:acme:market-equity:2026-06-30",
        "issuer_id": "issuer:acme",
        "concept": "market_equity_value",
        "value_type": "number",
        "value": 5_012_500_000,
        "unit": "currency_units",
        "currency": "USD",
        "period": {"start": None, "end": receipt.trading_date},
        "calculator_id": "market-equity-round-trip",
        "calculator_version": "1.0.0",
        "input_fact_ids": [quote.fact_id, shares.fact_id],
        "input_assumption_ids": [],
        "input_calculation_ids": [],
        "input_period_ids": [],
        "input_bindings": {"quote": quote.fact_id, "current_common_shares": shares.fact_id},
        "code_sha256": "a" * 64,
        "generated_at": "2026-07-14T01:00:02Z",
        "input_fingerprint": "0" * 64,
        "output_fingerprint": "0" * 64,
    }
    calculation = build_calculation_result(
        calculation_payload,
        facts={quote.fact_id: quote, shares.fact_id: shares},
        assumptions={},
        calculations={},
    )
    graph = replace_graph(
        graph,
        documents=graph.documents + (source,),
        facts=graph.facts + (quote, phase5c_shares, shares),
        calculations=graph.calculations + (calculation,),
    )
    current_shares = compile_quote_date_current_common_shares(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        expected_market_access=access,
    )
    assert current_shares.status == "eligible"
    assert current_shares.share_basis_decision is not None
    share_basis = current_shares.share_basis_decision
    context = MarketReferenceValidationContext(
        context_id="market-reference-context:acme:2026-06-30",
        price_blind_artifact=freeze.artifact,
        security_compilation_result=security,
        market_access_result=access,
        current_share_compilation_result=current_shares,
        raw_evidence_locator=RAW_LOCATOR,
    )
    graph = replace_graph(
        graph,
        market_reference_validation_contexts=(context,),
    )
    claim_control = {
        "status": "passed",
        "current_share_numeric_root_fact_ids": [shares.fact_id],
        "included_claim_root_fact_ids": [],
        "excluded_claim_root_fact_ids": [OPTION_ROOT_ID],
        "blocked_claim_root_fact_ids": [],
        "overlap_fact_ids": [],
        "check_fingerprint": claim_control_fingerprint(
            price_blind_input_fingerprint=access.price_blind_input_fingerprint,
            share_basis_decision_fingerprint=share_basis.fingerprint,
            claim_control_authority_fingerprint=context.claim_control_authority.fingerprint,
            current_share_numeric_root_fact_ids=(shares.fact_id,),
            excluded_claim_root_fact_ids=(OPTION_ROOT_ID,),
        ),
    }
    payload = {
        "schema_version": "4.0.0",
        "snapshot_id": (
            f"market-reference:issuer:acme:{receipt.trading_date}:"
            f"{governed.raw_response_sha256[:20]}"
        ),
        "issuer_id": "issuer:acme",
        "data_cutoff_date": access.data_cutoff_date,
        "status": "validated",
        "market_policy_id": "market-reference",
        "market_policy_version": "4.0.0",
        "authorization_handoff_id": access.authorization_handoff_id,
        "authorization_handoff_fingerprint": freeze.handoffs[-1].fingerprint,
        "component_lock_sha256": freeze.artifact.to_dict()["component_lock_sha256"],
        "market_access_result_fingerprint": access.fingerprint,
        "market_quote_request": {
            "request_id": request.request_id,
            "request_fingerprint": request.request_fingerprint,
        },
        "governed_market_quote_receipt": {
            "receipt_id": receipt.receipt_id,
            "receipt_fingerprint": governed.fingerprint,
        },
        "authority_lineage": {
            "authority_sha256": governed.authority_sha256,
            "provider_registry_sha256": governed.provider_registry_sha256,
            "provider_registration_sha256": governed.provider_registration_sha256,
            "adapter_sha256": governed.adapter_sha256,
            "parser_sha256": governed.parser_sha256,
            "calendar_registry_sha256": governed.calendar_registry_sha256,
            "calendar_dataset_sha256": governed.calendar_dataset_sha256,
            "calendar_selection_fingerprint": governed.calendar_selection_fingerprint,
            "provider_evidence_sha256": governed.fingerprint,
        },
        "security": {
            "security_id": security.decision.security_id,
            "ticker": security.decision.ticker,
            "mic": security.decision.exchange,
            "share_class": security.decision.share_class,
            "security_compilation_fingerprint": security.fingerprint,
            "security_evidence_closure_sha256": security.evidence_closure.closure_sha256,
        },
        "trading_date": receipt.trading_date,
        "quote_timestamp": receipt.quote_timestamp,
        "quote_retrieved_at": receipt.retrieved_at,
        "quote_price_decimal": receipt.quote_price,
        "quote_unit": "currency_per_share",
        "quote_currency": receipt.quote_currency,
        "source_authority_kind": "human_reviewed_file",
        "evidence_mode": governed.evidence_mode,
        "usage_scope": "test_only",
        "numeric_evidence": {
            "encoding": "canonical_decimal",
            "authoritative_decimal": receipt.quote_price,
            "binary64_hex": None,
        },
        "raw_evidence": {
            "store_kind": "repository_fixture",
            "locator": RAW_LOCATOR,
            "content_type": "application/json",
            "raw_response_sha256": governed.raw_response_sha256,
            "parser_replay_fingerprint": "0" * 64,
        },
        "quote_source_document_id": source.document_id,
        "quote_source_locator": quote_locator,
        "quote_fact_id": quote.fact_id,
        "share_basis": {
            "decision_id": share_basis.decision_id,
            "decision_fingerprint": share_basis.fingerprint,
            "basis_kind": share_basis.basis_kind,
            "evidence_kind": share_basis.evidence_kind,
            "as_of_date": share_basis.as_of_date,
            "quote_date": share_basis.quote_date,
            "shares_outstanding_fact_id": shares.fact_id,
            "current_common_shares_outstanding_decimal": "100000000",
            "share_unit": "shares",
            "split_factor_decimal": "1",
            "corporate_action_evidence_bindings": [
                {
                    "contract_type": contract_type,
                    "object_id": object_id,
                    "fingerprint": fingerprint,
                }
                for contract_type, object_id, fingerprint in (
                    current_shares.evidence_closure.object_fingerprints
                )
                if contract_type in {"SourceDocument", "Fact", "Claim"}
            ],
            "claim_control_check": claim_control,
        },
        "market_equity": {
            "calculation_id": calculation.calculation_id,
            "value_decimal": "5012500000",
            "unit": "currency_units",
            "currency": "USD",
        },
        "price_blind_input_fingerprint": access.price_blind_input_fingerprint,
        "protected_mckinsey_sha256": access.protected_mckinsey_sha256,
        "protected_penman_assumptions_sha256": (access.protected_penman_assumptions_sha256),
        "future_kernel_request_v2": {
            "share_denominator_fact_id": shares.fact_id,
            "share_denominator_kind": "current_common_shares_outstanding",
            "share_denominator_evidence_kind": share_basis.evidence_kind,
            "mapping_fingerprint": future_request_v2_mapping_fingerprint(
                price_blind_input_fingerprint=access.price_blind_input_fingerprint,
                shares_outstanding_fact_id=shares.fact_id,
                evidence_kind=share_basis.evidence_kind,
            ),
        },
        "market_evidence_closure_sha256": "0" * 64,
        "snapshot_fingerprint": "0" * 64,
    }
    payload["raw_evidence"]["parser_replay_fingerprint"] = parser_replay_fingerprint(
        payload,
        receipt,
    )
    payload["market_evidence_closure_sha256"] = market_evidence_closure_sha256(
        graph,
        payload,
        freeze.handoffs[-1],
        context,
    )
    payload["snapshot_fingerprint"] = _snapshot_fingerprint(payload)
    snapshot = MarketReferenceSnapshot(**payload)
    graph = replace_graph(graph, market_reference_snapshots=(snapshot,))
    return graph, snapshot, context, access, calculation


def replace_calculation(
    graph: ContractGraph,
    calculation: CalculationResult,
) -> ContractGraph:
    return replace_graph(
        graph,
        calculations=tuple(
            calculation if item.calculation_id == calculation.calculation_id else item
            for item in graph.calculations
        ),
    )
