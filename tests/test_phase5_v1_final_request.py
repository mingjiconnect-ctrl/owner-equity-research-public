from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError, dataclass, replace
from decimal import Decimal, localcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

import owner_research
from owner_research.calculation_integrity import build_calculation_result
from owner_research.contracts import Fact, SourceDocument
from owner_research.fingerprints import canonical_json, canonical_sha256, freeze, to_json_value
from owner_research.research_bundle_policies import dependency_closure_sha256
from owner_research.research_bundle_validation import dependency_closure
from owner_research.validation import ContractGraph
from owner_research.valuation_current_share_compiler import (
    CURRENT_SHARE_COMPILATION_POLICY_ID,
    CURRENT_SHARE_COMPILATION_POLICY_VERSION,
    CurrentShareCompilationResult,
)
from owner_research.valuation_final_request import (
    FinalValuationRequestCompilationResult,
    _compile_from_artifact,
)
from owner_research.valuation_kernel_projection import (
    KernelNumericProjectionWitness,
    project_current_share_lineage,
)

ROOT = Path(__file__).parents[1]
_KERNEL_ENV = os.environ.get("OWNER_VALUATION_REPO")
KERNEL = (
    Path(_KERNEL_ENV).expanduser().resolve()
    if _KERNEL_ENV
    else ROOT.parent / "owner-valuation-kernel"
)
EXAMPLE = KERNEL / "examples" / "synthetic_nonfinancial.json"
KERNEL_AVAILABLE = bool(_KERNEL_ENV) and (KERNEL / ".git").exists() and EXAMPLE.is_file()
requires_private_kernel = pytest.mark.skipif(
    not KERNEL_AVAILABLE,
    reason="pinned private kernel checkout is unavailable",
)


@dataclass(frozen=True, slots=True)
class _TestShareClosure:
    output_share_fact_id: str
    closure_sha256: str
    object_fingerprints: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True, slots=True)
class _TestShareDecision:
    fingerprint: str
    share_fact_id: str


@dataclass(frozen=True, slots=True)
class _TestSharePath:
    status: str
    path_kind: str


def _document(identifier: str, *, document_type: str = "10-Q") -> SourceDocument:
    return SourceDocument(
        schema_version="1.0.0",
        document_id=identifier,
        issuer_id="SYNTH",
        document_type=document_type,
        period={"start": "2026-01-01", "end": "2026-07-10"},
        published_date="2026-07-10",
        retrieved_at="2026-07-10T21:00:00Z",
        source_url=f"https://www.sec.gov/Archives/edgar/data/1/{identifier}.htm",
        authority_level="primary_regulatory",
        content_sha256=canonical_sha256({"document": identifier}),
    )


def _share_fact(
    identifier: str,
    concept: str,
    value: int,
    source: SourceDocument,
    *,
    end: str = "2026-07-10",
    derivation: str | None = None,
    parents: tuple[str, ...] = (),
) -> Fact:
    return Fact(
        schema_version="2.0.0",
        fact_id=identifier,
        issuer_id="SYNTH",
        concept=concept,
        value_type="number",
        value=value,
        unit="shares",
        currency=None,
        period={"start": None, "end": end},
        source_document_id=source.document_id,
        source_locator=f"shares://{identifier}",
        derivation=derivation,
        parent_fact_ids=parents,
        confidence="high",
    )


def _prepared_share_lineage(
    *,
    output: Fact,
    documents: tuple[SourceDocument, ...],
    facts: tuple[Fact, ...],
    path_kind: str,
    canonical_rollforward=None,
    typed_current: bool = False,
):
    closure_payload = dict(
        output_share_fact_id=output.fact_id,
        closure_sha256=canonical_sha256(
            {"facts": [item.fingerprint for item in facts], "path": path_kind}
        ),
        object_fingerprints=tuple(("Fact", item.fact_id, item.fingerprint) for item in facts),
    )
    decision_payload = dict(
        fingerprint=canonical_sha256({"decision": path_kind}),
        share_fact_id=output.fact_id,
    )
    if typed_current:
        closure = _TestShareClosure(**closure_payload)
        decision = _TestShareDecision(**decision_payload)
        current = CurrentShareCompilationResult(
            policy_id=CURRENT_SHARE_COMPILATION_POLICY_ID,
            policy_version=CURRENT_SHARE_COMPILATION_POLICY_VERSION,
            issuer_id="SYNTH",
            data_cutoff_date="2026-07-10",
            security_id="security:SYNTH:common",
            quote_date="2026-07-10",
            status="eligible",
            output_fact=output,
            share_basis_decision=decision,
            evidence_closure=closure,
            path_decisions=(_TestSharePath(status="selected", path_kind=path_kind),),
            issue_codes=(),
            canonical_rollforward=canonical_rollforward,
        )
    else:
        closure = SimpleNamespace(**closure_payload)
        decision = SimpleNamespace(**decision_payload)
        current = SimpleNamespace(
            status="eligible",
            output_fact=output,
            share_basis_decision=decision,
            evidence_closure=closure,
            path_decisions=(SimpleNamespace(status="selected", path_kind=path_kind),),
            issue_codes=(),
            canonical_rollforward=canonical_rollforward,
            fingerprint=canonical_sha256({"current": path_kind, "output": output.fingerprint}),
        )
    snapshot = SimpleNamespace(
        share_basis={"shares_outstanding_fact_id": output.fact_id},
        trading_date="2026-07-10",
        data_cutoff_date="2026-07-10",
    )
    graph = SimpleNamespace(documents=documents, facts=facts)
    return SimpleNamespace(current_shares=current, snapshot=snapshot, graph=graph)


def test_direct_and_issued_share_projection_preserve_raw_semantics() -> None:
    source = _document("doc-shares")
    direct = _share_fact(
        "fact-current-common-shares",
        "common_shares_outstanding",
        10_000_000,
        source,
    )
    projected = project_current_share_lineage(
        _prepared_share_lineage(
            output=direct,
            documents=(source,),
            facts=(direct,),
            path_kind="direct_point_in_time",
        )
    )
    assert projected.status == "eligible"
    assert projected.facts[0]["raw"] is True
    assert projected.facts[0]["value"] == 10.0
    assert projected.arithmetic_steps[0]["operation"] == "direct"

    issued = _share_fact("fact-issued", "common_shares_issued", 12_000_000, source)
    treasury = _share_fact("fact-treasury", "treasury_shares", 2_000_000, source)
    output = _share_fact(
        "fact-current-issued",
        "common_shares_outstanding",
        10_000_000,
        source,
        derivation="issued-less-treasury/1.0.0",
        parents=(treasury.fact_id, issued.fact_id),
    )
    projected = project_current_share_lineage(
        _prepared_share_lineage(
            output=output,
            documents=(source,),
            facts=(issued, treasury, output),
            path_kind="issued_less_treasury",
        )
    )
    by_id = {item["fact_id"]: item for item in projected.facts}
    assert projected.status == "eligible"
    assert by_id[issued.fact_id]["raw"] is True
    assert by_id[treasury.fact_id]["raw"] is True
    assert by_id[output.fact_id]["raw"] is False
    assert by_id[output.fact_id]["parent_fact_ids"] == (
        issued.fact_id,
        treasury.fact_id,
    )
    assert by_id[output.fact_id]["derivation"] == ("common_shares_issued - treasury_shares")


def _rollforward_prepared(*, ambiguous_primary: bool = False, concept: str | None = None):
    opening_source = _document("doc-opening", document_type="10-K")
    event_source = _document("doc-event", document_type="8-K")
    corroborating_source = _document("doc-corroborating")
    opening = _share_fact(
        "fact-opening",
        "common_shares_outstanding",
        100_000_000,
        opening_source,
        end="2026-06-30",
    )
    research_concept = concept or "common_shares_repurchased_completed"
    first = _share_fact("fact-event-8k", research_concept, 5_000_000, event_source)
    second_source = event_source if ambiguous_primary else corroborating_source
    second = _share_fact("fact-event-10q", research_concept, 5_000_000, second_source)
    canonical = _share_fact(
        "derived:canonical-event",
        research_concept,
        5_000_000,
        event_source,
        derivation="cross-source-share-event-grouping/1.0.0",
        parents=(first.fact_id, second.fact_id),
    )
    output_value = 105_000_000 if "issued" in research_concept else 95_000_000
    output = _share_fact(
        "fact-current-rollforward",
        "common_shares_outstanding",
        output_value,
        event_source,
        derivation="completed-event-rollforward/2.0.0",
        parents=(opening.fact_id, canonical.fact_id),
    )
    members = tuple(
        SimpleNamespace(
            member_id=f"member:{fact.fact_id}",
            source_document_id=fact.source_document_id,
            fact=fact,
            fact_id=fact.fact_id,
            source_document=(
                event_source
                if fact.source_document_id == event_source.document_id
                else corroborating_source
            ),
        )
        for fact in (first, second)
    )
    materialization = SimpleNamespace(
        group_id="share-event-group:one",
        canonical_event_fact=canonical,
        canonical_event_fact_id=canonical.fact_id,
        primary_source_document_id=event_source.document_id,
        members=members,
        materialization_fingerprint=canonical_sha256(
            {"group": "one", "members": [item.fact_id for item in members]}
        ),
    )
    rollforward = SimpleNamespace(
        opening_share_fact_id=opening.fact_id,
        output_share_fact_id=output.fact_id,
        materializations=(materialization,),
    )
    return _prepared_share_lineage(
        output=output,
        documents=(opening_source, event_source, corroborating_source),
        facts=(opening, first, second, canonical, output),
        path_kind="completed_event_rollforward",
        canonical_rollforward=rollforward,
    )


def test_v2_rollforward_consumes_one_raw_representative_and_attests_all_sources() -> None:
    prepared = _rollforward_prepared()
    projected = project_current_share_lineage(prepared)
    assert projected.status == "eligible"
    output = next(item for item in projected.facts if item["fact_id"] == "fact-current-rollforward")
    assert output["value"] == 95.0
    assert output["parent_fact_ids"] == ("fact-opening", "fact-event-8k")
    assert "derived:canonical-event" not in output["parent_fact_ids"]
    assert all(
        item["raw"] is True for item in projected.facts if item["fact_id"] == "fact-event-8k"
    )
    step = projected.arithmetic_steps[-1]
    assert step["corroborating_member_fact_ids"] == (
        "fact-event-10q",
        "fact-event-8k",
    )
    assert projected.research_evidence_attestation is not None
    attested = set(projected.research_evidence_attestation["objects"])
    graph_facts = {item.fact_id: item for item in prepared.graph.facts}
    graph_documents = {item.document_id: item for item in prepared.graph.documents}
    assert ("Fact", "fact-event-8k", graph_facts["fact-event-8k"].fingerprint) in attested
    assert ("Fact", "fact-event-10q", graph_facts["fact-event-10q"].fingerprint) in attested
    assert (
        "SourceDocument",
        "doc-corroborating",
        graph_documents["doc-corroborating"].fingerprint,
    ) in attested
    assert canonical_sha256(projected.research_evidence_attestation) == (
        projected.research_evidence_sha256
    )
    first_attestation = projected.research_evidence_sha256

    reversed_material = prepared.current_shares.canonical_rollforward.materializations[0]
    reversed_material = SimpleNamespace(
        **{
            **vars(reversed_material),
            "members": tuple(reversed(reversed_material.members)),
        }
    )
    prepared.current_shares.canonical_rollforward.materializations = (reversed_material,)
    replay = project_current_share_lineage(prepared)
    assert replay.status == "eligible"
    assert replay.research_evidence_sha256 == first_attestation
    assert replay.facts == projected.facts


def test_rollforward_primary_ambiguity_and_specialist_events_fail_closed() -> None:
    ambiguous = project_current_share_lineage(_rollforward_prepared(ambiguous_primary=True))
    assert ambiguous.status == "blocked"
    assert not ambiguous.facts

    convertible = project_current_share_lineage(
        _rollforward_prepared(concept="convertible_shares_converted_completed")
    )
    assert convertible.status == "specialist_required"
    assert convertible.issue_codes == ("convertible_event_requires_specialist",)
    assert not convertible.facts

    warrant = project_current_share_lineage(
        _rollforward_prepared(concept="warrant_shares_exercised_completed")
    )
    assert warrant.status == "specialist_required"
    assert warrant.issue_codes == ("warrant_event_requires_specialist",)
    assert not warrant.facts

    empty = _rollforward_prepared()
    empty.current_shares.canonical_rollforward.materializations = ()
    empty_result = project_current_share_lineage(empty)
    assert empty_result.status == "blocked"
    assert not empty_result.facts


def test_issued_less_treasury_requires_one_measurement_date() -> None:
    source = _document("doc-issued-date-mismatch")
    issued = _share_fact(
        "fact-issued-date-mismatch",
        "common_shares_issued",
        12_000_000,
        source,
        end="2026-07-09",
    )
    treasury = _share_fact(
        "fact-treasury-date-mismatch",
        "treasury_shares",
        2_000_000,
        source,
    )
    output = _share_fact(
        "fact-current-date-mismatch",
        "common_shares_outstanding",
        10_000_000,
        source,
        derivation="issued-less-treasury/1.0.0",
        parents=(issued.fact_id, treasury.fact_id),
    )
    result = project_current_share_lineage(
        _prepared_share_lineage(
            output=output,
            documents=(source,),
            facts=(issued, treasury, output),
            path_kind="issued_less_treasury",
        )
    )
    assert result.status == "blocked"
    assert not result.facts


def _request_ready_case(
    *,
    quote_decimal: str = "28",
    current_share_count: int = 10_000_000,
):
    example = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    base_ledger = copy.deepcopy(example["fact_ledger"])
    removed = {
        "fact-market-price-per-current-common-share",
        "fact-market-equity",
        "fact-current-common-shares",
    }
    base_ledger["facts"] = [item for item in base_ledger["facts"] if item["fact_id"] not in removed]
    assumptions = copy.deepcopy(example["assumption_ledger"])
    for item in assumptions["assumptions"]:
        item["value"] = float(item["value"])
    assumptions["assumptions"].sort(key=lambda item: item["assumption_id"])
    assumptions["fact_ledger_fingerprint"] = canonical_sha256(base_ledger)

    share_source = _document("doc-current-shares")
    current = _share_fact(
        "fact-current-common-shares",
        "common_shares_outstanding",
        current_share_count,
        share_source,
    )
    legal_name = Fact(
        schema_version="2.0.0",
        fact_id="fact-issuer-legal-name",
        issuer_id="SYNTH",
        concept="issuer_legal_name",
        value_type="text",
        value="Synthetic Corporation",
        unit=None,
        currency=None,
        period={"start": None, "end": "2026-07-10"},
        source_document_id=share_source.document_id,
        source_locator="cover:legal-name",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    share_prepared = _prepared_share_lineage(
        output=current,
        documents=(share_source,),
        facts=(current, legal_name),
        path_kind="direct_point_in_time",
        typed_current=True,
    )
    market_source = SourceDocument(
        schema_version="1.0.0",
        document_id="doc-market-close",
        issuer_id="SYNTH",
        document_type="market-quote",
        period={"start": None, "end": "2026-07-10"},
        published_date="2026-07-10",
        retrieved_at="2026-07-10T21:10:00Z",
        source_url="https://market.example.invalid/reviewed/synth-close",
        authority_level="market_reference",
        content_sha256="b" * 64,
    )
    quote = Fact(
        schema_version="2.0.0",
        fact_id="fact-market-price-per-current-common-share",
        issuer_id="SYNTH",
        concept="market_quote_close",
        value_type="number",
        value=float(Decimal(quote_decimal)),
        unit="currency_per_share",
        currency="USD",
        period={"start": None, "end": "2026-07-10"},
        source_document_id=market_source.document_id,
        source_locator="market://request/receipt/parser",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    exact_market_equity = Decimal(quote_decimal) * current_share_count
    calc_payload = {
        "schema_version": "2.0.0",
        "calculation_id": "market-equity",
        "issuer_id": "SYNTH",
        "concept": "market_equity_value",
        "value_type": "number",
        "value": (
            int(exact_market_equity)
            if exact_market_equity == exact_market_equity.to_integral_value()
            else float(exact_market_equity)
        ),
        "unit": "currency_units",
        "currency": "USD",
        "period": {"start": None, "end": "2026-07-10"},
        "calculator_id": "reviewed-close-times-current-common-shares",
        "calculator_version": "1.0.0",
        "code_sha256": "c" * 64,
        "input_fact_ids": (quote.fact_id, current.fact_id),
        "input_assumption_ids": (),
        "input_calculation_ids": (),
        "input_period_ids": (),
        "input_bindings": {"quote": quote.fact_id, "shares": current.fact_id},
        "generated_at": "2026-07-10T21:10:00Z",
    }
    calculation = build_calculation_result(
        calc_payload,
        facts={quote.fact_id: quote, current.fact_id: current},
        assumptions={},
        calculations={},
    )
    phase5c = {
        "specialist_route": "none",
        "method_panels": {
            "mckinsey": {"status": "ready_for_phase5d"},
            "penman": {"status": "ready_for_phase5d"},
        },
        "reconciliation_result": {
            "phase5b_readiness_result": {
                "classification": {
                    "specialist_route": "none",
                    "company_type": "nonfinancial_operating_company",
                    "rationale": example["company"]["classification_rationale"],
                    "mapped_fact_ids": example["company"]["source_fact_ids"],
                }
            },
            "fact_decisions": [
                {
                    "purpose": "adjusted_total_liabilities",
                    "disposition": "emitted",
                    "term_bindings": [
                        {
                            "input_role": "total_liabilities",
                            "fact_ids": [
                                example["accounting_checks"]["balance_sheet"]["liabilities_fact_id"]
                            ],
                        },
                        {
                            "input_role": "equity_classified_non_common_claims",
                            "fact_ids": [],
                        },
                    ],
                }
            ],
            "checks": {
                "balance_sheet": {
                    "status": "reconciles_independently",
                    "role_fact_ids": {
                        "total_assets": example["accounting_checks"]["balance_sheet"][
                            "assets_fact_id"
                        ],
                        "adjusted_total_liabilities": example["accounting_checks"]["balance_sheet"][
                            "liabilities_fact_id"
                        ],
                        "common_equity": example["accounting_checks"]["balance_sheet"][
                            "equity_fact_id"
                        ],
                    },
                    "stock_root_fact_ids": {
                        "adjusted_total_liabilities": [
                            example["accounting_checks"]["balance_sheet"]["liabilities_fact_id"]
                        ]
                    },
                },
                "clean_surplus": {
                    "status": "reconciles_independently",
                    "role_fact_ids": {
                        "beginning_common_equity": example["accounting_checks"]["clean_surplus"][
                            "beginning_equity_fact_id"
                        ],
                        "comprehensive_income_attributable_to_common": example["accounting_checks"][
                            "clean_surplus"
                        ]["comprehensive_income_fact_id"],
                        "net_distributions_to_owners": example["accounting_checks"][
                            "clean_surplus"
                        ]["net_distributions_fact_id"],
                        "ending_common_equity": example["accounting_checks"]["clean_surplus"][
                            "ending_equity_fact_id"
                        ],
                    },
                },
            },
        },
        "routing_assessments": {
            key: {
                "status": (
                    "pending_phase5d"
                    if key == "credible_near_term_earnings"
                    else "unsatisfied"
                    if key == "required_data_complete"
                    else "satisfied"
                ),
                "value": None
                if key == "credible_near_term_earnings"
                else False
                if key == "required_data_complete"
                else True,
                "rationale": value["rationale"],
                "evidence_fact_ids": value["source_fact_ids"],
            }
            for key, value in example["routing_assessments"].items()
        },
        "quality_result": {
            "status_by_method": {"mckinsey": "pass", "penman": "pass"},
            "kernel_quality_issues": [],
            "issue_decisions": [],
        },
        "method_view_result": {
            "method_views": {"mckinsey": [], "penman": []},
            "adjustment_decisions": [],
        },
        "equity_bridge_result": {
            "bridge_items": example["mckinsey"]["equity_bridge"]["items"],
            "role_assertions": example["mckinsey"]["equity_bridge"]["role_assertions"],
        },
    }
    kernel_identity = json.loads((ROOT / "component-lock.json").read_text())["valuation_kernel"]
    artifact = {
        "issuer_id": "SYNTH",
        "data_cutoff_date": "2026-07-10",
        "price_blind_input_fingerprint": "1" * 64,
        "protected_mckinsey_sha256": "2" * 64,
        "protected_penman_assumptions_sha256": "3" * 64,
        "component_lock_sha256": "4" * 64,
        "kernel_identity": kernel_identity,
        "reviewed_assumptions": {
            "augmented_fact_ledger_payload": base_ledger,
            "assumption_ledger_payload": assumptions,
            "assumption_entries_sha256": canonical_sha256(assumptions["assumptions"]),
        },
        "phase5c_readiness": phase5c,
        "mckinsey_inputs": {
            "base_invested_capital_fact_id": example["mckinsey"]["base_invested_capital_fact_id"],
            "scenario_payload": {"scenarios": example["mckinsey"]["scenarios"]},
        },
        "penman_inputs": {
            "current_noa_fact_id": example["penman"]["current_noa_fact_id"],
            "net_financial_obligations_fact_id": example["penman"][
                "net_financial_obligations_fact_id"
            ],
            "penman_payload": {
                key: value
                for key, value in example["penman"].items()
                if key
                not in {
                    "current_noa_fact_id",
                    "net_financial_obligations_fact_id",
                    "market_equity_value_fact_id",
                }
            },
        },
    }
    snapshot = SimpleNamespace(
        snapshot_id="market-reference:SYNTH:2026-07-10",
        status="validated",
        fingerprint="d" * 64,
        issuer_id="SYNTH",
        data_cutoff_date="2026-07-10",
        trading_date="2026-07-10",
        quote_currency="USD",
        quote_price_decimal=quote_decimal,
        quote_fact_id=quote.fact_id,
        quote_source_document_id=market_source.document_id,
        raw_evidence={"raw_response_sha256": market_source.content_sha256},
        authority_lineage={"provider_registration_sha256": "1" * 64},
        market_access_result_fingerprint="5" * 64,
        market_quote_request={
            "request_id": "market-request:SYNTH:2026-07-10",
            "request_fingerprint": "6" * 64,
        },
        governed_market_quote_receipt={
            "receipt_id": "market-receipt:SYNTH:2026-07-10",
            "receipt_fingerprint": "7" * 64,
        },
        authorization_handoff_id="valuation-handoff:SYNTH:run:v4",
        authorization_handoff_fingerprint="a" * 64,
        share_basis={
            "shares_outstanding_fact_id": current.fact_id,
            "current_common_shares_outstanding_decimal": str(current_share_count),
        },
        market_equity={
            "calculation_id": calculation.calculation_id,
            "value_decimal": format(exact_market_equity, "f"),
        },
        security={"ticker": "SYNTH", "security_id": "security:SYNTH:common"},
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        protected_mckinsey_sha256=artifact["protected_mckinsey_sha256"],
        protected_penman_assumptions_sha256=artifact["protected_penman_assumptions_sha256"],
        component_lock_sha256=artifact["component_lock_sha256"],
    )
    share_prepared.snapshot = snapshot
    share_prepared.market_source = market_source
    share_prepared.quote_fact = quote
    share_prepared.market_equity_calculation = calculation
    request = SimpleNamespace(
        request_id=snapshot.market_quote_request["request_id"],
        request_fingerprint=snapshot.market_quote_request["request_fingerprint"],
        provider_id="provider:reviewed-file-v1",
        price_basis="reviewed_unadjusted_regular_session_daily_close",
        security_id=snapshot.security["security_id"],
        authorization_handoff_id=snapshot.authorization_handoff_id,
        data_cutoff_date=snapshot.data_cutoff_date,
    )
    receipt = SimpleNamespace(
        receipt_id=snapshot.governed_market_quote_receipt["receipt_id"],
        request_id=request.request_id,
        request_fingerprint=request.request_fingerprint,
        provider_id=request.provider_id,
        security_id=request.security_id,
        authorization_handoff_id=request.authorization_handoff_id,
        data_cutoff_date=request.data_cutoff_date,
    )
    governed = SimpleNamespace(
        receipt=receipt,
        fingerprint=snapshot.governed_market_quote_receipt["receipt_fingerprint"],
        provider_registration_sha256=snapshot.authority_lineage["provider_registration_sha256"],
        raw_response_sha256=snapshot.raw_evidence["raw_response_sha256"],
    )
    access = SimpleNamespace(
        status="eligible",
        issuer_id=snapshot.issuer_id,
        data_cutoff_date=snapshot.data_cutoff_date,
        price_blind_input_fingerprint=snapshot.price_blind_input_fingerprint,
        protected_mckinsey_sha256=snapshot.protected_mckinsey_sha256,
        protected_penman_assumptions_sha256=(snapshot.protected_penman_assumptions_sha256),
        fingerprint=snapshot.market_access_result_fingerprint,
        request=request,
        receipt=governed,
    )
    base_graph = ContractGraph(
        documents=(share_source, market_source),
        facts=(current, legal_name, quote),
        calculations=(calculation,),
    )
    research_closure = dependency_closure(base_graph, (legal_name.fact_id,))
    research_dependency_sha = dependency_closure_sha256(
        [
            (kind, identifier, item.fingerprint)
            for identifier, (kind, item) in research_closure.items()
        ]
    )
    bundle = SimpleNamespace(
        bundle_id="research-bundle:SYNTH:2026-07-10",
        issuer_id="SYNTH",
        data_cutoff_date="2026-07-10",
        bundle_fingerprint="8" * 64,
        dependency_closure_sha256=research_dependency_sha,
        module_references=({"object_ids": (legal_name.fact_id,)},),
    )
    handoff = SimpleNamespace(
        handoff_id=snapshot.authorization_handoff_id,
        state="market_reference_allowed",
        fingerprint=snapshot.authorization_handoff_fingerprint,
        issuer_id="SYNTH",
        data_cutoff_date="2026-07-10",
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        research_bundle_dependency_sha256=research_dependency_sha,
        component_lock_sha256=snapshot.component_lock_sha256,
    )
    share_prepared.graph = ContractGraph(
        documents=base_graph.documents,
        facts=base_graph.facts,
        calculations=base_graph.calculations,
        research_bundles=(bundle,),
        market_reference_snapshots=(snapshot,),
        valuation_handoffs=(handoff,),
        market_reference_validation_contexts=(
            SimpleNamespace(
                context_id="market-context:SYNTH:2026-07-10",
                fingerprint="e" * 64,
                market_access_result=access,
                current_share_compilation_result=share_prepared.current_shares,
            ),
        ),
    )
    share_prepared.fingerprint = canonical_sha256(
        {"snapshot": vars(snapshot), "quote": quote.fingerprint}
    )
    return artifact, share_prepared, example


def _rebind_research_bundle(
    prepared,
    *,
    facts: tuple[Fact, ...] | None = None,
    root_fact_ids: tuple[str, ...] | None = None,
) -> None:
    graph = prepared.graph
    graph = replace(graph, facts=facts if facts is not None else graph.facts)
    bundle = graph.research_bundles[0]
    handoff = graph.valuation_handoffs[0]
    if root_fact_ids is not None:
        bundle.module_references = ({"object_ids": root_fact_ids},)
    closure = dependency_closure(
        graph,
        tuple(
            object_id
            for reference in bundle.module_references
            for object_id in reference["object_ids"]
        ),
    )
    dependency_sha = dependency_closure_sha256(
        [(kind, identifier, item.fingerprint) for identifier, (kind, item) in closure.items()]
    )
    bundle.dependency_closure_sha256 = dependency_sha
    handoff.research_bundle_dependency_sha256 = dependency_sha
    prepared.graph = graph


@requires_private_kernel
def test_final_request_is_append_only_rebinds_assumptions_and_runs_rc2() -> None:
    artifact, prepared, _example = _request_ready_case()
    result = _compile_from_artifact(
        prepared=prepared,
        artifact=artifact,
        kernel_repository=KERNEL,
    )
    assert result.status == "compiled"
    assert result.request_payload is not None
    request = result.request_payload
    base = artifact["reviewed_assumptions"]["augmented_fact_ledger_payload"]
    final = request["fact_ledger"]
    for item in base["sources"]:
        assert canonical_json(item) == canonical_json(
            next(value for value in final["sources"] if value["source_id"] == item["source_id"])
        )
    for item in base["facts"]:
        assert canonical_json(item) == canonical_json(
            next(value for value in final["facts"] if value["fact_id"] == item["fact_id"])
        )
    assert canonical_json(request["assumption_ledger"]["assumptions"]) == canonical_json(
        artifact["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"]
    )
    assert request["assumption_ledger"]["fact_ledger_fingerprint"] == canonical_sha256(final)
    share_id = request["mckinsey"]["equity_bridge"]["share_denominator_fact_id"]
    market = next(item for item in final["facts"] if item["concept"] == "market_equity_value")
    assert market["parent_fact_ids"][0] == "fact-market-price-per-current-common-share"
    assert market["parent_fact_ids"][1] == share_id
    assert request["penman"]["market_equity_value_fact_id"] == market["fact_id"]
    assert request["company"]["name"] == "Synthetic Corporation"
    assert result.company_name_fact_id == "fact-issuer-legal-name"
    assert result.company_legal_name_value == "Synthetic Corporation"
    assert result.company_name_fact_fingerprint == next(
        item.fingerprint
        for item in prepared.graph.facts
        if item.fact_id == result.company_name_fact_id
    )
    assert result.company_name_source_document_id == "doc-current-shares"
    assert result.company_name_source_document_fingerprint == next(
        item.fingerprint
        for item in prepared.graph.documents
        if item.document_id == result.company_name_source_document_id
    )
    assert result.fact_ledger_result is not None
    market_source = next(
        item for item in final["sources"] if item["source_id"] == "doc-market-close"
    )
    assert market_source["publisher"] == "provider:reviewed-file-v1"
    assert "reviewed_unadjusted_regular_session_daily_close" in market_source["title"]
    assert result.fact_ledger_result.market_provider_id == "provider:reviewed-file-v1"
    assert result.fact_ledger_result.market_access_result_fingerprint == (
        prepared.snapshot.market_access_result_fingerprint
    )
    assert result.fact_ledger_result.market_provider_registration_sha256 == "1" * 64
    assert result.fact_ledger_result.market_raw_response_sha256 == "b" * 64
    assert result.fact_ledger_result.market_source_document_fingerprint == (
        prepared.market_source.fingerprint
    )
    assert result.fact_ledger_result.market_quote_fact_fingerprint == (
        prepared.quote_fact.fingerprint
    )
    assert result.fact_ledger_result.market_equity_calculation_fingerprint == (
        prepared.market_equity_calculation.fingerprint
    )

    script = (
        "import json,sys; from owner_valuation import run_dual_panel; "
        "json.dump(run_dual_panel(json.load(sys.stdin)),sys.stdout,sort_keys=True)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=result.canonical_request_json,
        text=True,
        capture_output=True,
        check=True,
        env={"PYTHONPATH": str(KERNEL / "src")},
    )
    output = json.loads(completed.stdout)
    assert output["panels"]["mckinsey"]
    assert output["panels"]["penman"]


@requires_private_kernel
def test_request_compile_is_decimal_context_independent_and_does_not_execute_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, prepared, _example = _request_ready_case(quote_decimal="0.1")
    fingerprints = []
    for precision in (2, 4, 28):
        with localcontext() as context:
            context.prec = precision
            result = _compile_from_artifact(
                prepared=prepared,
                artifact=artifact,
                kernel_repository=KERNEL,
            )
        assert result.status == "compiled"
        fingerprints.append(result.fingerprint)
    assert len(set(fingerprints)) == 1

    original_run = subprocess.run

    def allow_git_only(*args, **kwargs):
        command = args[0]
        if not command or command[0] != "git":
            raise AssertionError("request compilation executed mutable checkout code")
        return original_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", allow_git_only)
    result = _compile_from_artifact(
        prepared=prepared,
        artifact=artifact,
        kernel_repository=KERNEL,
    )
    assert result.status == "compiled"


@requires_private_kernel
def test_compilation_receipt_rejects_self_hashed_nested_binding_mutations() -> None:
    artifact, prepared, _example = _request_ready_case()
    result = _compile_from_artifact(
        prepared=prepared,
        artifact=artifact,
        kernel_repository=KERNEL,
    )
    assert result.request_payload is not None

    different_ledger = to_json_value(result.request_payload)
    different_ledger["fact_ledger"]["entity_id"] = "FORGED"
    with pytest.raises(ValueError, match="ledger receipts"):
        replace(
            result,
            request_payload=freeze(different_ledger),
            canonical_request_json=canonical_json(different_ledger),
            request_sha256=canonical_sha256(different_ledger),
        )

    assert result.assumption_ledger_result is not None
    mismatched_assumption_receipt = replace(
        result.assumption_ledger_result,
        prior_fact_ledger_fingerprint="9" * 64,
    )
    with pytest.raises(ValueError, match="ledger receipts"):
        replace(result, assumption_ledger_result=mismatched_assumption_receipt)

    different_market_binding = to_json_value(result.request_payload)
    different_market_binding["mckinsey"]["equity_bridge"]["share_denominator_fact_id"] = (
        different_market_binding["company"]["source_fact_ids"][0]
    )
    with pytest.raises(ValueError, match="generated market Facts"):
        replace(
            result,
            request_payload=freeze(different_market_binding),
            canonical_request_json=canonical_json(different_market_binding),
            request_sha256=canonical_sha256(different_market_binding),
        )

    forged_company = to_json_value(result.request_payload)
    forged_company["company"]["name"] = "Forged Corporation"
    with pytest.raises(ValueError, match="ledger receipts"):
        replace(
            result,
            company_legal_name_value="Forged Corporation",
            request_payload=freeze(forged_company),
            canonical_request_json=canonical_json(forged_company),
            request_sha256=canonical_sha256(forged_company),
        )

    assert result.fact_ledger_result is not None
    with pytest.raises(ValueError, match="governed market evidence"):
        replace(
            result.fact_ledger_result,
            market_access_result_fingerprint="8" * 64,
        )
    with pytest.raises(ValueError, match="governed market evidence"):
        replace(
            result.fact_ledger_result,
            market_source_document_fingerprint="9" * 64,
        )
    forged_ledger = to_json_value(result.fact_ledger_result.fact_ledger_payload)
    market_source = next(
        item
        for item in forged_ledger["sources"]
        if item["source_id"] == result.fact_ledger_result.market_source_document_id
    )
    market_source["publisher"] = "provider:forged"
    with pytest.raises(ValueError, match="governed market evidence"):
        replace(
            result.fact_ledger_result,
            market_provider_id="provider:forged",
            market_source_ref_fingerprint=canonical_sha256(market_source),
            fact_ledger_payload=freeze(forged_ledger),
        )


@requires_private_kernel
def test_final_request_fails_closed_on_date_specialist_mapping_and_tamper() -> None:
    artifact, prepared, _example = _request_ready_case()
    bad_date = copy.deepcopy(artifact)
    bad_date["reviewed_assumptions"]["augmented_fact_ledger_payload"]["valuation_date"] = (
        "2026-07-09"
    )
    bad_date["reviewed_assumptions"]["assumption_ledger_payload"]["fact_ledger_fingerprint"] = (
        canonical_sha256(bad_date["reviewed_assumptions"]["augmented_fact_ledger_payload"])
    )
    with pytest.raises(ValueError, match="identity/date/currency"):
        _compile_from_artifact(prepared=prepared, artifact=bad_date, kernel_repository=KERNEL)

    specialist = copy.deepcopy(artifact)
    specialist["phase5c_readiness"]["specialist_route"] = "sum_of_parts"
    with pytest.raises(ValueError, match="not ready"):
        _compile_from_artifact(prepared=prepared, artifact=specialist, kernel_repository=KERNEL)

    mapping = copy.deepcopy(artifact)
    mapping["kernel_identity"]["commit"] = "0" * 40
    with pytest.raises(ValueError, match="does not bind"):
        _compile_from_artifact(prepared=prepared, artifact=mapping, kernel_repository=KERNEL)

    tampered = copy.deepcopy(artifact)
    tampered["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"][0]["value"] += 1
    with pytest.raises(ValueError, match="do not replay"):
        _compile_from_artifact(prepared=prepared, artifact=tampered, kernel_repository=KERNEL)


@requires_private_kernel
def test_final_request_rejects_liability_root_and_forecast_axis_shortcuts() -> None:
    artifact, prepared, example = _request_ready_case()
    wrong_liability = copy.deepcopy(artifact)
    wrong_liability["phase5c_readiness"]["reconciliation_result"]["fact_decisions"][0][
        "term_bindings"
    ][0]["fact_ids"] = [example["accounting_checks"]["balance_sheet"]["assets_fact_id"]]
    with pytest.raises(ValueError, match="raw total-liabilities root"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=wrong_liability,
            kernel_repository=KERNEL,
        )

    non_common_claim = copy.deepcopy(artifact)
    non_common_claim["phase5c_readiness"]["reconciliation_result"]["fact_decisions"][0][
        "term_bindings"
    ][1]["fact_ids"] = ["fact-preferred"]
    with pytest.raises(ValueError, match="non-common claims require specialist"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=non_common_claim,
            kernel_repository=KERNEL,
        )

    shifted_axis = copy.deepcopy(artifact)
    shifted_axis["mckinsey_inputs"]["scenario_payload"]["scenarios"][0]["forecast"][0][
        "period_end"
    ] = "2027-08-01"
    with pytest.raises(ValueError, match="annual axis"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=shifted_axis,
            kernel_repository=KERNEL,
        )

    valid_nonanniversary = copy.deepcopy(artifact)
    mckinsey_axis = (
        "2027-07-11",
        "2028-07-11",
        "2029-07-11",
        "2030-07-11",
        "2031-07-11",
    )
    penman_axis = mckinsey_axis[:2]
    for scenario in valid_nonanniversary["mckinsey_inputs"]["scenario_payload"]["scenarios"]:
        for row, period_end in zip(scenario["forecast"], mckinsey_axis, strict=True):
            row["period_end"] = period_end
    for row, period_end in zip(
        valid_nonanniversary["penman_inputs"]["penman_payload"]["forecast"],
        penman_axis,
        strict=True,
    ):
        row["period_end"] = period_end
    for row, period_end in zip(
        valid_nonanniversary["penman_inputs"]["penman_payload"]["market_challenge_path"],
        ("2029-07-11", "2030-07-11", "2031-07-11"),
        strict=True,
    ):
        row["period_end"] = period_end
    result = _compile_from_artifact(
        prepared=prepared,
        artifact=valid_nonanniversary,
        kernel_repository=KERNEL,
    )
    assert result.status == "compiled"


@requires_private_kernel
def test_assumption_ledger_requires_float_bytes_unique_ids_and_sorted_order() -> None:
    artifact, prepared, _example = _request_ready_case()

    integer_value = copy.deepcopy(artifact)
    integer_value["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"][0][
        "value"
    ] = 200
    integer_value["reviewed_assumptions"]["assumption_entries_sha256"] = canonical_sha256(
        integer_value["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"]
    )
    with pytest.raises(ValueError, match="canonical rc.2 representation"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=integer_value,
            kernel_repository=KERNEL,
        )

    unsorted = copy.deepcopy(artifact)
    assumptions = unsorted["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"]
    assumptions[0], assumptions[1] = assumptions[1], assumptions[0]
    unsorted["reviewed_assumptions"]["assumption_entries_sha256"] = canonical_sha256(assumptions)
    with pytest.raises(ValueError, match="uniquely sorted"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=unsorted,
            kernel_repository=KERNEL,
        )

    duplicate = copy.deepcopy(artifact)
    assumptions = duplicate["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"]
    assumptions.insert(1, copy.deepcopy(assumptions[0]))
    duplicate["reviewed_assumptions"]["assumption_entries_sha256"] = canonical_sha256(assumptions)
    with pytest.raises(ValueError, match="uniquely sorted"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=duplicate,
            kernel_repository=KERNEL,
        )


@requires_private_kernel
def test_company_and_market_authority_are_evidence_bound() -> None:
    artifact, prepared, _example = _request_ready_case()

    missing = prepared
    missing.graph = replace(
        prepared.graph,
        facts=tuple(item for item in prepared.graph.facts if item.concept != "issuer_legal_name"),
    )
    with pytest.raises(ValueError, match="ResearchBundle dependency closure"):
        _compile_from_artifact(
            prepared=missing,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    _artifact, conflict_case, _example = _request_ready_case()
    legal = next(item for item in conflict_case.graph.facts if item.concept == "issuer_legal_name")
    conflicting = Fact(
        schema_version="2.0.0",
        fact_id="fact-issuer-legal-name-conflict",
        issuer_id=legal.issuer_id,
        concept=legal.concept,
        value_type="text",
        value="Synthetic Holdings Corporation",
        unit=None,
        currency=None,
        period=legal.period,
        source_document_id=legal.source_document_id,
        source_locator="cover:legal-name-conflict",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    _rebind_research_bundle(
        conflict_case,
        facts=(*conflict_case.graph.facts, conflicting),
        root_fact_ids=(legal.fact_id, conflicting.fact_id),
    )
    with pytest.raises(ValueError, match="lacks one official"):
        _compile_from_artifact(
            prepared=conflict_case,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    _artifact, no_context, _example = _request_ready_case()
    no_context.graph = replace(
        no_context.graph,
        market_reference_validation_contexts=(),
    )
    with pytest.raises(ValueError, match="matched validation context"):
        _compile_from_artifact(
            prepared=no_context,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    _artifact, mismatched_provider, _example = _request_ready_case()
    mismatched_context = mismatched_provider.graph.market_reference_validation_contexts[0]
    mismatched_context.market_access_result.receipt.receipt.provider_id = "provider:forged"
    with pytest.raises(ValueError, match="provider identity"):
        _compile_from_artifact(
            prepared=mismatched_provider,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    _artifact, mismatched_request, _example = _request_ready_case()
    mismatched_receipt = mismatched_request.graph.market_reference_validation_contexts[
        0
    ].market_access_result.receipt.receipt
    mismatched_receipt.request_fingerprint = "f" * 64
    with pytest.raises(ValueError, match="provider identity"):
        _compile_from_artifact(
            prepared=mismatched_request,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    _artifact, stale_authorization, _example = _request_ready_case()
    stale_authorization.graph.valuation_handoffs[0].state = "price_blind_input_frozen"
    with pytest.raises(ValueError, match="ResearchBundle binding"):
        _compile_from_artifact(
            prepared=stale_authorization,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    _artifact, forged_authorization, _example = _request_ready_case()
    forged_authorization.graph.valuation_handoffs[0].fingerprint = "b" * 64
    with pytest.raises(ValueError, match="ResearchBundle binding"):
        _compile_from_artifact(
            prepared=forged_authorization,
            artifact=artifact,
            kernel_repository=KERNEL,
        )


@requires_private_kernel
def test_prepared_market_objects_replay_unique_graph_and_context_ownership() -> None:
    artifact, substituted_source, _example = _request_ready_case()
    substituted_source.market_source = replace(
        substituted_source.market_source,
        source_url="https://forged.example.invalid/close",
    )
    with pytest.raises(ValueError, match="unique graph object"):
        _compile_from_artifact(
            prepared=substituted_source,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    artifact, substituted_quote, _example = _request_ready_case()
    substituted_quote.quote_fact = replace(substituted_quote.quote_fact, value=29.0)
    with pytest.raises(ValueError, match="unique graph object"):
        _compile_from_artifact(
            prepared=substituted_quote,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    artifact, substituted_calculation, _example = _request_ready_case()
    substituted_calculation.market_equity_calculation = replace(
        substituted_calculation.market_equity_calculation,
        code_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="unique graph object"):
        _compile_from_artifact(
            prepared=substituted_calculation,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    artifact, substituted_shares, _example = _request_ready_case()
    substituted_shares.current_shares = replace(
        substituted_shares.current_shares,
        issuer_id="OTHER",
    )
    with pytest.raises(ValueError, match="validation context"):
        _compile_from_artifact(
            prepared=substituted_shares,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    artifact, future_source_case, _example = _request_ready_case()
    future_source = replace(
        future_source_case.market_source,
        published_date="2026-07-11",
    )
    future_source_case.market_source = future_source
    future_source_case.graph = replace(
        future_source_case.graph,
        documents=tuple(
            future_source if item.document_id == future_source.document_id else item
            for item in future_source_case.graph.documents
        ),
    )
    with pytest.raises(ValueError, match="validation context"):
        _compile_from_artifact(
            prepared=future_source_case,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    artifact, duplicate_case, _example = _request_ready_case()
    duplicate_case.graph = replace(
        duplicate_case.graph,
        documents=(*duplicate_case.graph.documents, duplicate_case.market_source),
    )
    with pytest.raises(ValueError, match="unique graph object"):
        _compile_from_artifact(
            prepared=duplicate_case,
            artifact=artifact,
            kernel_repository=KERNEL,
        )

    artifact, context_mismatch, _example = _request_ready_case()
    context_mismatch.graph.market_reference_validation_contexts[
        0
    ].current_share_compilation_result = replace(
        context_mismatch.current_shares,
        issuer_id="OTHER",
    )
    with pytest.raises(ValueError, match="validation context"):
        _compile_from_artifact(
            prepared=context_mismatch,
            artifact=artifact,
            kernel_repository=KERNEL,
        )


@requires_private_kernel
def test_price_blind_ledger_rejects_market_lineage_without_overblocking_benchmarks() -> None:
    artifact, prepared, example = _request_ready_case()
    injected = copy.deepcopy(artifact)
    market_fact = copy.deepcopy(
        next(
            item
            for item in example["fact_ledger"]["facts"]
            if item["concept"] == "market_equity_value"
        )
    )
    market_fact["fact_id"] = "fact-injected-price-blind-market-equity"
    injected["reviewed_assumptions"]["augmented_fact_ledger_payload"]["facts"].append(market_fact)
    injected["reviewed_assumptions"]["assumption_ledger_payload"]["fact_ledger_fingerprint"] = (
        canonical_sha256(injected["reviewed_assumptions"]["augmented_fact_ledger_payload"])
    )
    with pytest.raises(ValueError, match="market-price lineage"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=injected,
            kernel_repository=KERNEL,
        )

    benchmark = copy.deepcopy(artifact)
    root = copy.deepcopy(
        benchmark["reviewed_assumptions"]["augmented_fact_ledger_payload"]["facts"][0]
    )
    root.update(
        {
            "fact_id": "fact-nonprice-market-benchmark",
            "concept": "industry_hurdle_rate_benchmark",
            "category": "market_reference",
            "value": 0.1,
            "unit": "decimal",
            "currency": None,
        }
    )
    benchmark["reviewed_assumptions"]["augmented_fact_ledger_payload"]["facts"].append(root)
    benchmark["reviewed_assumptions"]["assumption_ledger_payload"]["fact_ledger_fingerprint"] = (
        canonical_sha256(benchmark["reviewed_assumptions"]["augmented_fact_ledger_payload"])
    )
    result = _compile_from_artifact(
        prepared=prepared,
        artifact=benchmark,
        kernel_repository=KERNEL,
    )
    assert result.status == "compiled"


@requires_private_kernel
def test_market_equity_projection_uses_projected_quote_times_projected_shares() -> None:
    artifact, prepared, _example = _request_ready_case(
        quote_decimal="0.1",
        current_share_count=3_000_000,
    )
    result = _compile_from_artifact(
        prepared=prepared,
        artifact=artifact,
        kernel_repository=KERNEL,
    )
    assert result.status == "compiled"
    assert result.fact_ledger_result is not None
    witness = result.fact_ledger_result.market_equity_projection_witness
    assert witness.model_decimal == "0.3"
    assert witness.kernel_value == 0.1 * 3.0
    assert witness.projection_delta_decimal != "0"
    assert witness.exact_binary64_decimal == format(
        Decimal.from_float(0.1 * 3.0),
        "f",
    )


def test_decimal_projection_is_immutable_exact_and_internal_only() -> None:
    witness = KernelNumericProjectionWitness.compile(
        label="quote", authoritative_decimal=Decimal("28.125")
    )
    assert witness.kernel_value == 28.125
    assert witness.binary64_hex
    with pytest.raises(FrozenInstanceError):
        witness.binary64_hex = "0" * 16  # type: ignore[misc]
    drift = KernelNumericProjectionWitness.compile(
        label="quote-drift",
        authoritative_decimal=Decimal("28.1250000000000000001"),
    )
    assert drift.projection_delta_decimal != "0"
    assert drift.exact_binary64_decimal == format(
        Decimal.from_float(drift.kernel_value),
        "f",
    )
    with pytest.raises(ValueError, match="binary64"):
        KernelNumericProjectionWitness.compile(
            label="huge",
            authoritative_decimal=Decimal("1e10000"),
        )
    with pytest.raises(ValueError, match="subnormal"):
        KernelNumericProjectionWitness.compile(
            label="subnormal",
            authoritative_decimal=Decimal("5e-324"),
        )
    with pytest.raises(ValueError, match="underflows"):
        KernelNumericProjectionWitness.compile(
            label="underflow",
            authoritative_decimal=Decimal("1e-4000"),
        )
    with pytest.raises(ValueError, match="finite and positive"):
        KernelNumericProjectionWitness.compile(
            label="negative-zero",
            authoritative_decimal=Decimal("-0"),
        )
    scientific = witness.to_dict()
    scientific["canonical_json_number_token"] = "2.8125e1"
    with pytest.raises(ValueError, match="not canonical"):
        KernelNumericProjectionWitness(**scientific)
    assert not hasattr(owner_research, "compile_final_valuation_request")
    assert not hasattr(owner_research, "project_current_share_lineage")
    assert not hasattr(owner_research, "run_dual_panel")

    result = FinalValuationRequestCompilationResult(
        status="blocked",
        issuer_id="SYNTH",
        valuation_date="2026-07-10",
        price_blind_input_fingerprint="a" * 64,
        prepared_market_reference_fingerprint=None,
        company_legal_name_value=None,
        company_name_fact_id=None,
        company_name_fact_fingerprint=None,
        company_name_source_document_id=None,
        company_name_source_document_fingerprint=None,
        company_identity_binding_sha256=None,
        fact_ledger_result=None,
        assumption_ledger_result=None,
        request_payload=None,
        canonical_request_json=None,
        request_sha256=None,
        issue_codes=("blocked",),
    )
    assert result.status == "blocked"


def test_decimal_projection_ignores_ambient_context_and_binds_rc2_operation_order() -> None:
    fingerprints = []
    for precision in (2, 4, 28):
        with localcontext() as context:
            context.prec = precision
            fingerprints.append(
                KernelNumericProjectionWitness.compile(
                    label="context-independent",
                    authoritative_decimal=Decimal("28.1250000000000000001"),
                ).fingerprint
            )
    assert len(set(fingerprints)) == 1

    source = _document("doc-binary64-share-order")
    issued = _share_fact(
        "fact-issued-binary64-order",
        "common_shares_issued",
        9_007_199_254_740_993,
        source,
    )
    treasury = _share_fact(
        "fact-treasury-binary64-order",
        "treasury_shares",
        1,
        source,
    )
    output = _share_fact(
        "fact-current-binary64-order",
        "common_shares_outstanding",
        9_007_199_254_740_992,
        source,
        derivation="issued-less-treasury/1.0.0",
        parents=(treasury.fact_id, issued.fact_id),
    )
    projected = project_current_share_lineage(
        _prepared_share_lineage(
            output=output,
            documents=(source,),
            facts=(output, treasury, issued),
            path_kind="issued_less_treasury",
        )
    )
    assert projected.status == "eligible"
    facts = {item["concept"]: item for item in projected.facts}
    assert facts["common_shares_outstanding"]["value"] == (
        facts["common_shares_issued"]["value"] - facts["treasury_shares"]["value"]
    )
    output_witness = next(
        item for item in projected.numeric_witnesses if item.label == f"share:{output.fact_id}"
    )
    assert (
        output_witness.projection_delta_decimal
        == projected.arithmetic_steps[0]["output_projection_delta_decimal"]
    )
