"""Deterministic MarketReferenceSnapshot v4 builder for the Phase 5 v1 slice."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from typing import Any

from .calculation_integrity import build_calculation_result
from .contracts import CalculationResult, Fact, MarketReferenceSnapshot, SourceDocument
from .fingerprints import canonical_sha256
from .validation import ContractGraph
from .valuation_current_share_compiler import CurrentShareCompilationResult
from .valuation_handoff_policies import (
    MARKET_REFERENCE_POLICY_ID,
    MARKET_REFERENCE_POLICY_VERSION,
)
from .valuation_handoff_validation import (
    claim_control_fingerprint,
    future_request_v2_mapping_fingerprint,
    market_evidence_closure_sha256,
    parser_replay_fingerprint,
)
from .valuation_market_provider import (
    _MAX_RAW_EVIDENCE_BYTES,
    REVIEWED_FILE_USAGE_SCOPE,
    MarketReferenceAcquisition,
    _read_regular_file,
    exact_decimal_product,
    replay_reviewed_market_reference,
)
from .valuation_market_reference_types import MarketReferenceValidationContext
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult
from .valuation_security_identity import SecurityIdentityCompilationResult
from .valuation_share_event_integration_types import CurrentShareEvidenceClosureV2


def _append_unique(values: tuple[Any, ...], item: Any, identifier: str) -> tuple[Any, ...]:
    existing = tuple(
        value
        for value in values
        if getattr(value, identifier) == getattr(item, identifier)
    )
    if not existing:
        return values + (item,)
    if len(existing) != 1 or existing[0] != item:
        raise ValueError(f"market evidence collides with {getattr(item, identifier)}")
    return values


def _fact_number(value: Decimal, label: str) -> int | float:
    if value == value.to_integral_value():
        return int(value)
    projected = float(value)
    if Decimal(str(projected)) != value:
        raise ValueError(f"{label} cannot round-trip through the current Fact contract")
    return projected


def _calculation_code_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class PreparedMarketReference:
    snapshot: MarketReferenceSnapshot
    market_source: SourceDocument
    quote_fact: Fact
    market_equity_calculation: CalculationResult
    current_shares: CurrentShareCompilationResult
    graph: ContractGraph

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(
            {
                "snapshot": self.snapshot,
                "market_source": self.market_source,
                "quote_fact": self.quote_fact,
                "market_equity_calculation": self.market_equity_calculation,
                "current_shares": self.current_shares,
            }
        )


def _graph_with_current_share_lineage(
    graph: ContractGraph,
    current_shares: CurrentShareCompilationResult,
) -> ContractGraph:
    output = current_shares.output_fact
    if output is None:
        raise ValueError("current-share compilation has no output Fact")
    facts = graph.facts
    canonical = current_shares.canonical_rollforward
    if canonical is not None:
        for materialization in canonical.materializations:
            facts = _append_unique(
                facts,
                materialization.canonical_event_fact,
                "fact_id",
            )
    facts = _append_unique(facts, output, "fact_id")
    return replace(graph, facts=facts)


def build_reviewed_market_reference_snapshot(
    *,
    price_blind_artifact_directory: Path,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    acquisition: MarketReferenceAcquisition,
    current_shares: CurrentShareCompilationResult,
) -> PreparedMarketReference:
    """Re-read governed evidence, then build one release-candidate Snapshot."""

    acquisition = replay_reviewed_market_reference(
        price_blind_artifact_directory=price_blind_artifact_directory,
        graph=graph,
        expected_freeze=expected_freeze,
        expected_security=expected_security,
        expected_acquisition=acquisition,
    )
    if current_shares.status != "eligible" or current_shares.share_basis_decision is None:
        raise ValueError("Snapshot requires an eligible current-share compilation")
    access = acquisition.access_result
    request = access.request
    governed = access.receipt
    security = expected_security.decision
    security_closure = expected_security.evidence_closure
    if (
        access.status != "eligible"
        or request is None
        or governed is None
        or security is None
        or security_closure is None
    ):
        raise ValueError("Snapshot requires governed market and security evidence")
    receipt = governed.receipt
    quote = acquisition.quote
    raw_bytes = _read_regular_file(
        acquisition.raw_evidence_file,
        label="raw market evidence",
        maximum_bytes=_MAX_RAW_EVIDENCE_BYTES,
    )
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    if raw_sha != quote.raw_evidence_sha256 or raw_sha != governed.raw_response_sha256:
        raise ValueError("raw market evidence changed after review")
    share_fact = current_shares.output_fact
    assert share_fact is not None
    quote_decimal = Decimal(quote.close_decimal)
    shares_decimal = Decimal(str(share_fact.value))
    market_equity_decimal = exact_decimal_product(
        quote.close_decimal,
        format(shares_decimal, "f"),
    )
    quote_value = _fact_number(quote_decimal, "quote")
    market_equity_value = _fact_number(market_equity_decimal, "market equity")

    source_id = f"doc:{quote.issuer_id}:reviewed-market:{raw_sha[:24]}"
    source = SourceDocument(
        schema_version="1.0.0",
        document_id=source_id,
        issuer_id=quote.issuer_id,
        document_type="market-quote",
        period={"start": None, "end": quote.trading_date},
        published_date=quote.source_published_date,
        retrieved_at=quote.source_retrieved_at,
        source_url=quote.source_url,
        authority_level="market_reference",
        content_sha256=raw_sha,
    )
    quote_locator = f"market://{request.request_id}/{receipt.receipt_id}/{governed.parser_sha256}"
    quote_fact = Fact(
        schema_version="2.0.0",
        fact_id=f"fact:{quote.issuer_id}:reviewed-close:{quote.trading_date}:{raw_sha[:16]}",
        issuer_id=quote.issuer_id,
        concept="market_quote_close",
        value_type="number",
        value=quote_value,
        unit="currency_per_share",
        currency=quote.currency,
        period={"start": None, "end": quote.trading_date},
        source_document_id=source.document_id,
        source_locator=quote_locator,
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    calculation_payload = {
        "schema_version": "2.0.0",
        "calculation_id": (
            f"calc:{quote.issuer_id}:market-equity:{quote.trading_date}:{raw_sha[:16]}"
        ),
        "issuer_id": quote.issuer_id,
        "concept": "market_equity_value",
        "value_type": "number",
        "value": market_equity_value,
        "unit": "currency_units",
        "currency": quote.currency,
        "period": {"start": None, "end": quote.trading_date},
        "calculator_id": "reviewed-close-times-current-common-shares",
        "calculator_version": "1.0.0",
        "code_sha256": _calculation_code_sha256(),
        "input_fact_ids": (quote_fact.fact_id, share_fact.fact_id),
        "input_assumption_ids": (),
        "input_calculation_ids": (),
        "input_period_ids": (),
        "input_bindings": {
            "quote": quote_fact.fact_id,
            "current_common_shares": share_fact.fact_id,
        },
        "generated_at": receipt.retrieved_at,
    }
    calculation = build_calculation_result(
        calculation_payload,
        facts={quote_fact.fact_id: quote_fact, share_fact.fact_id: share_fact},
        assumptions={},
        calculations={},
    )
    working = _graph_with_current_share_lineage(graph, current_shares)
    working = replace(
        working,
        documents=_append_unique(working.documents, source, "document_id"),
        facts=_append_unique(working.facts, quote_fact, "fact_id"),
        calculations=_append_unique(
            working.calculations,
            calculation,
            "calculation_id",
        ),
    )
    context = MarketReferenceValidationContext(
        context_id=f"market-reference-context:{quote.issuer_id}:{quote.trading_date}:{raw_sha[:16]}",
        price_blind_artifact=expected_freeze.artifact,
        security_compilation_result=expected_security,
        market_access_result=access,
        current_share_compilation_result=current_shares,
        raw_evidence_locator=f"reviewed://sha256/{raw_sha}",
        raw_evidence_path=acquisition.raw_evidence_file,
        provider_evidence_sha256=quote.review_receipt_sha256,
        price_blind_artifact_directory=price_blind_artifact_directory,
        price_blind_freeze_result=expected_freeze,
        market_reference_request=acquisition.request,
        reviewed_quote=acquisition.quote,
        authorization_reservation=acquisition.authorization_reservation,
        authorization_consumption=acquisition.authorization_consumption,
        review_file_path=acquisition.review_file,
    )
    authority = context.claim_control_authority
    share_closure = current_shares.evidence_closure
    assert share_closure is not None
    numeric_roots = tuple(
        sorted(
            share_closure.ultimate_numeric_root_fact_ids
            if isinstance(share_closure, CurrentShareEvidenceClosureV2)
            else share_closure.numeric_root_fact_ids
        )
    )
    excluded_roots = tuple(sorted(authority.excluded_option_root_fact_ids))
    claim_control = {
        "status": "passed",
        "current_share_numeric_root_fact_ids": numeric_roots,
        "included_claim_root_fact_ids": (),
        "excluded_claim_root_fact_ids": excluded_roots,
        "blocked_claim_root_fact_ids": (),
        "overlap_fact_ids": (),
        "check_fingerprint": claim_control_fingerprint(
            price_blind_input_fingerprint=access.price_blind_input_fingerprint,
            share_basis_decision_fingerprint=current_shares.share_basis_decision.fingerprint,
            claim_control_authority_fingerprint=authority.fingerprint,
            current_share_numeric_root_fact_ids=numeric_roots,
            excluded_claim_root_fact_ids=excluded_roots,
        ),
    }
    evidence_bindings = tuple(
        {
            "contract_type": contract_type,
            "object_id": object_id,
            "fingerprint": fingerprint,
        }
        for contract_type, object_id, fingerprint in share_closure.object_fingerprints
        if contract_type in {"SourceDocument", "Fact", "Claim"}
        and object_id
        in set(current_shares.share_basis_decision.corporate_action_evidence_ids)
    )
    authorization = expected_freeze.handoffs[-1]
    payload: dict[str, Any] = {
        "schema_version": "4.0.0",
        "snapshot_id": f"market-reference:{quote.issuer_id}:{quote.trading_date}:{raw_sha[:20]}",
        "issuer_id": quote.issuer_id,
        "data_cutoff_date": access.data_cutoff_date,
        "status": "validated",
        "market_policy_id": MARKET_REFERENCE_POLICY_ID,
        "market_policy_version": MARKET_REFERENCE_POLICY_VERSION,
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_handoff_fingerprint": authorization.fingerprint,
        "component_lock_sha256": hashlib.sha256(
            working.component_lock_path.read_bytes()
        ).hexdigest(),
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
            "provider_evidence_sha256": quote.review_receipt_sha256,
        },
        "security": {
            "security_id": security.security_id,
            "ticker": security.ticker,
            "mic": security.exchange,
            "share_class": security.share_class,
            "security_compilation_fingerprint": expected_security.fingerprint,
            "security_evidence_closure_sha256": security_closure.closure_sha256,
        },
        "trading_date": quote.trading_date,
        "quote_timestamp": quote.quote_timestamp,
        "quote_retrieved_at": receipt.retrieved_at,
        "quote_price_decimal": quote.close_decimal,
        "quote_unit": "currency_per_share",
        "quote_currency": quote.currency,
        "source_authority_kind": quote.authority_kind,
        "evidence_mode": "human_reviewed_file",
        "usage_scope": REVIEWED_FILE_USAGE_SCOPE,
        "numeric_evidence": {
            "encoding": "canonical_decimal",
            "authoritative_decimal": quote.close_decimal,
            "binary64_hex": None,
        },
        "raw_evidence": {
            "store_kind": "reviewed_file",
            "locator": f"reviewed://sha256/{raw_sha}",
            "content_type": quote.raw_content_type,
            "raw_response_sha256": raw_sha,
            "parser_replay_fingerprint": "0" * 64,
        },
        "quote_source_document_id": source.document_id,
        "quote_source_locator": quote_locator,
        "quote_fact_id": quote_fact.fact_id,
        "share_basis": {
            "decision_id": current_shares.share_basis_decision.decision_id,
            "decision_fingerprint": current_shares.share_basis_decision.fingerprint,
            "basis_kind": current_shares.share_basis_decision.basis_kind,
            "evidence_kind": current_shares.share_basis_decision.evidence_kind,
            "as_of_date": current_shares.share_basis_decision.as_of_date,
            "quote_date": current_shares.share_basis_decision.quote_date,
            "shares_outstanding_fact_id": share_fact.fact_id,
            "current_common_shares_outstanding_decimal": format(shares_decimal, "f"),
            "share_unit": "shares",
            "split_factor_decimal": current_shares.share_basis_decision.split_factor,
            "corporate_action_evidence_bindings": evidence_bindings,
            "claim_control_check": claim_control,
        },
        "market_equity": {
            "calculation_id": calculation.calculation_id,
            "value_decimal": format(market_equity_decimal, "f"),
            "unit": "currency_units",
            "currency": quote.currency,
        },
        "price_blind_input_fingerprint": access.price_blind_input_fingerprint,
        "protected_mckinsey_sha256": access.protected_mckinsey_sha256,
        "protected_penman_assumptions_sha256": access.protected_penman_assumptions_sha256,
        "future_kernel_request_v2": {
            "share_denominator_fact_id": share_fact.fact_id,
            "share_denominator_kind": "current_common_shares_outstanding",
            "share_denominator_evidence_kind": current_shares.share_basis_decision.evidence_kind,
            "mapping_fingerprint": future_request_v2_mapping_fingerprint(
                price_blind_input_fingerprint=access.price_blind_input_fingerprint,
                shares_outstanding_fact_id=share_fact.fact_id,
                evidence_kind=current_shares.share_basis_decision.evidence_kind,
            ),
        },
        "market_evidence_closure_sha256": "0" * 64,
        "snapshot_fingerprint": "0" * 64,
    }
    payload["raw_evidence"]["parser_replay_fingerprint"] = parser_replay_fingerprint(
        payload,
        receipt,
    )
    working_with_context = replace(
        working,
        market_reference_validation_contexts=(
            *working.market_reference_validation_contexts,
            context,
        ),
    )
    payload["market_evidence_closure_sha256"] = market_evidence_closure_sha256(
        working_with_context,
        payload,
        authorization,
        context,
    )
    fingerprint_payload = dict(payload)
    fingerprint_payload.pop("snapshot_fingerprint")
    payload["snapshot_fingerprint"] = canonical_sha256(fingerprint_payload)
    snapshot = MarketReferenceSnapshot(**payload)
    final_graph = replace(
        working_with_context,
        market_reference_snapshots=(
            *working_with_context.market_reference_snapshots,
            snapshot,
        ),
    )
    final_graph.validate()
    return PreparedMarketReference(
        snapshot=snapshot,
        market_source=source,
        quote_fact=quote_fact,
        market_equity_calculation=calculation,
        current_shares=current_shares,
        graph=final_graph,
    )


__all__ = ()
