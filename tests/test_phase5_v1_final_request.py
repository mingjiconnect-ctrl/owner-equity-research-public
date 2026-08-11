from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

import owner_research
from owner_research.calculation_integrity import build_calculation_result
from owner_research.contracts import Fact, SourceDocument
from owner_research.fingerprints import canonical_json, canonical_sha256
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
):
    closure = SimpleNamespace(
        closure_sha256=canonical_sha256(
            {"facts": [item.fingerprint for item in facts], "path": path_kind}
        ),
        object_fingerprints=tuple(
            ("Fact", item.fact_id, item.fingerprint) for item in facts
        ),
    )
    decision = SimpleNamespace(
        fingerprint=canonical_sha256({"decision": path_kind}),
        share_fact_id=output.fact_id,
    )
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

    issued = _share_fact(
        "fact-issued", "common_shares_issued", 12_000_000, source
    )
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
    assert by_id[output.fact_id]["derivation"] == (
        "common_shares_issued - treasury_shares"
    )


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
    output = next(
        item for item in projected.facts if item["fact_id"] == "fact-current-rollforward"
    )
    assert output["value"] == 95.0
    assert output["parent_fact_ids"] == ("fact-opening", "fact-event-8k")
    assert "derived:canonical-event" not in output["parent_fact_ids"]
    assert all(
        item["raw"] is True
        for item in projected.facts
        if item["fact_id"] == "fact-event-8k"
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


def test_rollforward_primary_ambiguity_and_convertible_fail_closed() -> None:
    ambiguous = project_current_share_lineage(_rollforward_prepared(ambiguous_primary=True))
    assert ambiguous.status == "blocked"
    assert not ambiguous.facts

    convertible = project_current_share_lineage(
        _rollforward_prepared(concept="convertible_shares_converted_completed")
    )
    assert convertible.status == "specialist_required"
    assert not convertible.facts


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
    base_ledger["facts"] = [
        item for item in base_ledger["facts"] if item["fact_id"] not in removed
    ]
    assumptions = copy.deepcopy(example["assumption_ledger"])
    assumptions["fact_ledger_fingerprint"] = canonical_sha256(base_ledger)

    share_source = _document("doc-current-shares")
    current = _share_fact(
        "fact-current-common-shares",
        "common_shares_outstanding",
        current_share_count,
        share_source,
    )
    share_prepared = _prepared_share_lineage(
        output=current,
        documents=(share_source,),
        facts=(current,),
        path_kind="direct_point_in_time",
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
                                example["accounting_checks"]["balance_sheet"][
                                    "liabilities_fact_id"
                                ]
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
                        "adjusted_total_liabilities": example["accounting_checks"][
                            "balance_sheet"
                        ]["liabilities_fact_id"],
                        "common_equity": example["accounting_checks"]["balance_sheet"][
                            "equity_fact_id"
                        ],
                    },
                    "stock_root_fact_ids": {
                        "adjusted_total_liabilities": [
                            example["accounting_checks"]["balance_sheet"][
                                "liabilities_fact_id"
                            ]
                        ]
                    },
                },
                "clean_surplus": {
                    "status": "reconciles_independently",
                    "role_fact_ids": {
                        "beginning_common_equity": example["accounting_checks"][
                            "clean_surplus"
                        ]["beginning_equity_fact_id"],
                        "comprehensive_income_attributable_to_common": example[
                            "accounting_checks"
                        ]["clean_surplus"]["comprehensive_income_fact_id"],
                        "net_distributions_to_owners": example["accounting_checks"][
                            "clean_surplus"
                        ]["net_distributions_fact_id"],
                        "ending_common_equity": example["accounting_checks"][
                            "clean_surplus"
                        ]["ending_equity_fact_id"],
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
            "role_assertions": example["mckinsey"]["equity_bridge"][
                "role_assertions"
            ],
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
            "base_invested_capital_fact_id": example["mckinsey"][
                "base_invested_capital_fact_id"
            ],
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
        issuer_id="SYNTH",
        data_cutoff_date="2026-07-10",
        trading_date="2026-07-10",
        quote_currency="USD",
        quote_price_decimal=quote_decimal,
        quote_fact_id=quote.fact_id,
        quote_source_document_id=market_source.document_id,
        raw_evidence={"raw_response_sha256": market_source.content_sha256},
        share_basis={
            "shares_outstanding_fact_id": current.fact_id,
            "current_common_shares_outstanding_decimal": str(current_share_count),
        },
        market_equity={
            "calculation_id": calculation.calculation_id,
            "value_decimal": format(exact_market_equity, "f"),
        },
        security={"ticker": "SYNTH"},
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        protected_mckinsey_sha256=artifact["protected_mckinsey_sha256"],
        protected_penman_assumptions_sha256=artifact[
            "protected_penman_assumptions_sha256"
        ],
        component_lock_sha256=artifact["component_lock_sha256"],
    )
    share_prepared.snapshot = snapshot
    share_prepared.market_source = market_source
    share_prepared.quote_fact = quote
    share_prepared.market_equity_calculation = calculation
    share_prepared.fingerprint = canonical_sha256(
        {"snapshot": vars(snapshot), "quote": quote.fingerprint}
    )
    return artifact, share_prepared, example


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
            next(
                value
                for value in final["sources"]
                if value["source_id"] == item["source_id"]
            )
        )
    for item in base["facts"]:
        assert canonical_json(item) == canonical_json(
            next(
                value
                for value in final["facts"]
                if value["fact_id"] == item["fact_id"]
            )
        )
    assert canonical_json(request["assumption_ledger"]["assumptions"]) == canonical_json(
        artifact["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"]
    )
    assert request["assumption_ledger"]["fact_ledger_fingerprint"] == canonical_sha256(final)
    share_id = request["mckinsey"]["equity_bridge"]["share_denominator_fact_id"]
    market = next(
        item for item in final["facts"] if item["concept"] == "market_equity_value"
    )
    assert market["parent_fact_ids"][0] == "fact-market-price-per-current-common-share"
    assert market["parent_fact_ids"][1] == share_id
    assert request["penman"]["market_equity_value_fact_id"] == market["fact_id"]

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
def test_final_request_fails_closed_on_date_specialist_mapping_and_tamper() -> None:
    artifact, prepared, _example = _request_ready_case()
    bad_date = copy.deepcopy(artifact)
    bad_date["reviewed_assumptions"]["augmented_fact_ledger_payload"][
        "valuation_date"
    ] = "2026-07-09"
    bad_date["reviewed_assumptions"]["assumption_ledger_payload"][
        "fact_ledger_fingerprint"
    ] = canonical_sha256(
        bad_date["reviewed_assumptions"]["augmented_fact_ledger_payload"]
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
    tampered["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"][0][
        "value"
    ] += 1
    with pytest.raises(ValueError, match="do not replay"):
        _compile_from_artifact(prepared=prepared, artifact=tampered, kernel_repository=KERNEL)


@requires_private_kernel
def test_final_request_rejects_liability_root_and_forecast_axis_shortcuts() -> None:
    artifact, prepared, example = _request_ready_case()
    wrong_liability = copy.deepcopy(artifact)
    wrong_liability["phase5c_readiness"]["reconciliation_result"]["fact_decisions"][
        0
    ]["term_bindings"][0]["fact_ids"] = [
        example["accounting_checks"]["balance_sheet"]["assets_fact_id"]
    ]
    with pytest.raises(ValueError, match="raw total-liabilities root"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=wrong_liability,
            kernel_repository=KERNEL,
        )

    non_common_claim = copy.deepcopy(artifact)
    non_common_claim["phase5c_readiness"]["reconciliation_result"]["fact_decisions"][
        0
    ]["term_bindings"][1]["fact_ids"] = ["fact-preferred"]
    with pytest.raises(ValueError, match="non-common claims require specialist"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=non_common_claim,
            kernel_repository=KERNEL,
        )

    shifted_axis = copy.deepcopy(artifact)
    shifted_axis["mckinsey_inputs"]["scenario_payload"]["scenarios"][0][
        "forecast"
    ][0]["period_end"] = "2027-07-11"
    with pytest.raises(ValueError, match="annual axis"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=shifted_axis,
            kernel_repository=KERNEL,
        )


@requires_private_kernel
def test_market_equity_projection_uses_projected_quote_times_projected_shares() -> None:
    artifact, prepared, _example = _request_ready_case(
        quote_decimal="0.1",
        current_share_count=3_000_000,
    )
    with pytest.raises(ValueError, match="upstream binary64 arithmetic"):
        _compile_from_artifact(
            prepared=prepared,
            artifact=artifact,
            kernel_repository=KERNEL,
        )


def test_decimal_projection_is_immutable_exact_and_internal_only() -> None:
    witness = KernelNumericProjectionWitness.compile(
        label="quote", authoritative_decimal=Decimal("28.125")
    )
    assert witness.kernel_value == 28.125
    assert witness.binary64_hex
    with pytest.raises(FrozenInstanceError):
        witness.binary64_hex = "0" * 16  # type: ignore[misc]
    with pytest.raises(ValueError, match="without numeric drift"):
        KernelNumericProjectionWitness.compile(
            label="quote",
            authoritative_decimal=Decimal("28.1250000000000000001"),
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
        fact_ledger_result=None,
        assumption_ledger_result=None,
        request_payload=None,
        canonical_request_json=None,
        request_sha256=None,
        issue_codes=("blocked",),
    )
    assert result.status == "blocked"
