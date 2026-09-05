from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
import test_phase5_v1_market_slice as market_slice_fixtures
from phase5_v1_public_kernel_fixture import (
    PUBLIC_KERNEL_REPOSITORY,
    install_public_kernel_schema_oracle,
    public_kernel_example,
)

import owner_research.valuation_market_provider as market_provider_module
from owner_research.contracts import Claim, Fact, SourceDocument
from owner_research.fingerprints import canonical_json, canonical_sha256
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.research_bundle_validation import dependency_closure
from owner_research.valuation_final_request import compile_final_valuation_request
from owner_research.valuation_market_snapshot import (
    build_reviewed_market_reference_snapshot,
)
from owner_research.valuation_owner_preparation import OwnerValuationPreparationResult
from owner_research.valuation_pinned_kernel import execute_in_authorized_container
from owner_research.valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindInputArtifact,
    _protected_mckinsey,
    _protected_penman,
)

FORECAST_PERIODS = (
    ("2026-07-01", "2027-06-30"),
    ("2027-07-01", "2028-06-30"),
)
CHALLENGE_PERIODS = (
    ("2028-07-01", "2029-06-30"),
    ("2029-07-01", "2030-06-30"),
)
SCENARIOS = ("black_swan", "bear", "base", "bull")
RUNTIME_ENV = (
    "OWNER_RESEARCH_KERNEL_CAS",
    "OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST",
    "OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST_FILE_SHA256",
    "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256",
)
TRUSTED_CONTAINER_ATTESTATION = Path("/run/owner-research/trusted-container-attestation.json")
EXPECTED_KERNEL_WHEEL_SHA256 = "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5"
EXPECTED_RUNNER_SHA256 = "1baebaaa11aab5165ff3d6d1e1567b2dfbc2dac2cd23576572112038ca16fd0b"
EXPECTED_RESULT_SCHEMA_SHA256 = "bbfed2049ed258b767002b74ff45fb6847eb5723ffd6c1d31c53cf119625a683"
EXPECTED_WHEEL_INVENTORY_SHA256 = "1caf6f35d5045714ef99952c2061f19e53597fa1f867a7c026c07cfa55462384"
EXPECTED_RUNTIME_AUTHORITY_SHA256 = (
    "0a317935d257e2fb406bc8efd9c90d42b1e572a6f8e6baa3c6d75b7cb48530dd"
)
EXPECTED_MATERIALIZER_SHA256 = "0f7117cb1d34cef5eac421d21f5931bcb0724eff64bc861ef72ace17941b219f"
EXPECTED_CONTAINER_IMAGE = (
    "docker.io/library/python@"
    "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
)
EXPECTED_CONTAINER_MANIFEST_DIGEST = (
    "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
)
EXPECTED_CONTAINER_CONFIG_DIGEST = (
    "sha256:d299dee73063206fe64248b8eb62cbef36f6baedfc2c5e2ef4c7618ad18efb3a"
)
EXPECTED_WORKFLOW_READ_ONLY_MOUNTS = [
    {"role": "candidate_workspace", "target": "/workspace"},
    {"role": "private_kernel_checkout", "target": "/private-kernel"},
    {"role": "binary_supply_wheelhouse", "target": "/supply"},
    {"role": "binary_supply_lock", "target": "/supply.lock"},
    {"role": "verified_research_wheel", "target": "/research-wheel"},
    {"role": "runtime_cas", "target": "/runtime-cas"},
    {"role": "trusted_attestation_directory", "target": "/run/owner-research"},
]
EXPECTED_WORKFLOW_WRITABLE_MOUNTS = [{"role": "canonical_summary_output", "target": "/output"}]
EXPECTED_REQUEST_SHA256 = "5a7af2d982dfbe92ed4d96deb0970536e0a0f979fcd2fef3860e2876f48cd478"
EXPECTED_PUBLIC_REQUEST_SHA256 = "818e5790ba5d667aba2a382c3ca2ee10266b9ba8a71c2bcebcdd4fbb6d7f26b7"
EXPECTED_RESULT_SHA256 = "b2f95009db924fd877956cfa18e7a2abaf4f15afe8aefe291528136bbabc01cb"
EXPECTED_MARKET_RECEIPT_ID = "market-quote-receipt:4b06a71dff87014673d09263"
EXPECTED_PUBLIC_MARKET_RECEIPT_ID = "market-quote-receipt:c2fe19f6eef193055bda7226"
EXPECTED_MARKET_RECEIPT_FINGERPRINT = (
    "dea812c989b1fcc04d7248a64651758d210598664fbca4d692cc289a3c3956d3"
)
EXPECTED_PUBLIC_MARKET_RECEIPT_FINGERPRINT = (
    "c5c062e2c933d89975dabc9d7f97f677aeae6704ce831f1be27f175303154317"
)
COMPANY_NAME = "Synthetic Nonfinancial Company"
COMPANY_NAME_FACT_ID = "fact:acme:issuer-legal-name"
COMPANY_NAME_SOURCE_ID = "doc:acme:legal-name:2025-10k"
ASSUMPTION_SOURCES = {
    "revenue": ["fact-revenue"],
    "nopat": ["fact-revenue", "fact-nopat"],
    "ending_invested_capital": ["fact-invested-capital"],
    "wacc": ["fact-risk-free", "fact-debt"],
    "terminal_growth": ["fact-revenue", "fact-market-growth"],
    "terminal_ronic": ["fact-invested-capital", "fact-nopat"],
    "terminal_margin": ["fact-revenue", "fact-nopat"],
    "terminal_roic": ["fact-invested-capital", "fact-nopat"],
    "steady_state_tolerance": ["fact-method-policy"],
    "sales": ["fact-revenue"],
    "operating_income_after_tax": ["fact-revenue", "fact-nopat"],
    "ending_noa": ["fact-noa"],
    "hurdle_rate": ["fact-risk-free", "fact-method-policy"],
    "growth_rate": ["fact-revenue", "fact-market-growth"],
}
_KERNEL_ENV = os.environ.get("OWNER_VALUATION_REPO")
_PRIVATE_KERNEL = Path(_KERNEL_ENV).expanduser().resolve() if _KERNEL_ENV else None
_PRIVATE_EXAMPLE = (
    _PRIVATE_KERNEL / "examples" / "synthetic_nonfinancial.json"
    if _PRIVATE_KERNEL is not None
    else None
)
PRIVATE_KERNEL_AVAILABLE = bool(
    _PRIVATE_KERNEL is not None
    and (_PRIVATE_KERNEL / ".git").is_dir()
    and _PRIVATE_EXAMPLE is not None
    and _PRIVATE_EXAMPLE.is_file()
)


@pytest.fixture(autouse=True)
def _repo_owned_public_kernel_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    if _KERNEL_ENV and not PRIVATE_KERNEL_AVAILABLE:
        pytest.fail("OWNER_VALUATION_REPO is not a usable pinned kernel checkout")
    if not _KERNEL_ENV:
        install_public_kernel_schema_oracle(monkeypatch)


def _bind_company_identity(graph):
    bundle = graph.research_bundles[0]
    source = SourceDocument(
        schema_version="1.0.0",
        document_id=COMPANY_NAME_SOURCE_ID,
        issuer_id=bundle.issuer_id,
        document_type="10-K",
        period={"start": "2025-01-01", "end": "2025-12-31"},
        published_date="2026-02-15",
        retrieved_at="2026-02-16T01:02:03Z",
        source_url=(
            "https://www.sec.gov/Archives/edgar/data/123/000000012326000001/acme-20251231.htm"
        ),
        authority_level="primary_regulatory",
        content_sha256=canonical_sha256({"fixture": "issuer-legal-name"}),
    )
    identity = Fact(
        schema_version="2.0.0",
        fact_id=COMPANY_NAME_FACT_ID,
        issuer_id=bundle.issuer_id,
        concept="issuer_legal_name",
        value_type="text",
        value=COMPANY_NAME,
        unit=None,
        currency=None,
        period={"start": None, "end": "2025-12-31"},
        source_document_id=source.document_id,
        source_locator="cover:registrant-name",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    claim = Claim(
        schema_version="1.0.0",
        claim_id="claim:acme:issuer-legal-name",
        issuer_id=bundle.issuer_id,
        statement=(f"The official filing identifies {COMPANY_NAME} as the legal issuer name."),
        as_of_date=bundle.data_cutoff_date,
        supporting_fact_ids=(identity.fact_id,),
        counterevidence_fact_ids=(),
        counterevidence_search_note=(
            "Checked the official filing cover page for the registrant legal name."
        ),
        confidence="high",
        falsification_condition=(
            "An official filing identifies a different registrant legal name."
        ),
    )
    review = graph.management_reviews[0]
    review = replace(
        review,
        claim_ids=tuple(sorted((*review.claim_ids, claim.claim_id))),
    )
    manifest = graph.manifests[0]
    input_hashes = dict(manifest.input_document_hashes)
    input_hashes[source.document_id] = source.content_sha256
    manifest = replace(manifest, input_document_hashes=input_hashes)
    base = replace(
        graph,
        documents=tuple(sorted((*graph.documents, source), key=lambda item: item.document_id)),
        facts=tuple(sorted((*graph.facts, identity), key=lambda item: item.fact_id)),
        claims=tuple(sorted((*graph.claims, claim), key=lambda item: item.claim_id)),
        management_reviews=(review,),
        manifests=(manifest,),
        research_bundles=(),
    )
    base.validate()
    rebuilt = build_research_bundle(base, run_id=manifest.run_id)
    completed = replace(
        base,
        manifests=(rebuilt.run_manifest,),
        research_bundles=(rebuilt.bundle,),
    )
    completed.validate()
    roots = tuple(
        str(object_id)
        for reference in rebuilt.bundle.module_references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(completed, roots)
    legal_names = tuple(
        item
        for contract_type, item in closure.values()
        if contract_type == "Fact" and item.concept == "issuer_legal_name"
    )
    assert legal_names == (identity,)
    assert source.document_id in rebuilt.bundle.source_document_ids
    assert source.issuer_id == rebuilt.bundle.issuer_id
    assert source.published_date <= rebuilt.bundle.data_cutoff_date
    assert source.authority_level == "primary_regulatory"
    return completed


def _assumption(
    identifier: str,
    *,
    concept: str,
    value: float,
    unit: str,
    scope: str,
    scenario: str | None,
) -> dict[str, Any]:
    return {
        "assumption_id": identifier,
        "value": value,
        "unit": unit,
        "concept": concept,
        "scope": scope,
        "rationale": "Named-human-reviewed price-blind dual-panel input.",
        "source_fact_ids": ASSUMPTION_SOURCES[concept],
        "scenario": scenario,
    }


def _request_ready_method_inputs() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    assumptions: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        forecast = []
        for index, (_start, end) in enumerate(FORECAST_PERIODS, start=1):
            values = {
                "revenue": (200.0, 220.0)[index - 1],
                "nopat": (20.0, 22.0)[index - 1],
                "ending_invested_capital": (110.0, 121.0)[index - 1],
            }
            ids = {
                concept: f"assumption:mckinsey:{scenario}:y{index}:{concept}" for concept in values
            }
            for concept, value in values.items():
                assumptions.append(
                    _assumption(
                        ids[concept],
                        concept=concept,
                        value=value,
                        unit="USD millions",
                        scope="mckinsey",
                        scenario=scenario,
                    )
                )
            forecast.append(
                {
                    "period_end": end,
                    "revenue_assumption_id": ids["revenue"],
                    "nopat_assumption_id": ids["nopat"],
                    "ending_invested_capital_assumption_id": ids["ending_invested_capital"],
                }
            )
        terminal_values = {
            "wacc": 0.12,
            "terminal_growth": 0.10,
            "terminal_ronic": 0.20,
            "terminal_margin": 0.10,
            "terminal_roic": 0.20,
            "steady_state_tolerance": 0.001,
        }
        terminal_ids = {
            concept: f"assumption:mckinsey:{scenario}:{concept}" for concept in terminal_values
        }
        for concept, value in terminal_values.items():
            assumptions.append(
                _assumption(
                    terminal_ids[concept],
                    concept=concept,
                    value=value,
                    unit="decimal",
                    scope="mckinsey",
                    scenario=scenario,
                )
            )
        scenarios.append(
            {
                "name": scenario,
                "wacc_assumption_id": terminal_ids["wacc"],
                "terminal_growth_assumption_id": terminal_ids["terminal_growth"],
                "terminal_ronic_assumption_id": terminal_ids["terminal_ronic"],
                "forecast": forecast,
                "steady_state": {
                    "terminal_nopat_margin_assumption_id": terminal_ids["terminal_margin"],
                    "terminal_roic_assumption_id": terminal_ids["terminal_roic"],
                    "tolerance_assumption_id": terminal_ids["steady_state_tolerance"],
                },
            }
        )

    penman_forecast = []
    for index, (_start, end) in enumerate(FORECAST_PERIODS, start=1):
        values = {
            "sales": (120.0, 132.0)[index - 1],
            "operating_income_after_tax": (18.0, 19.8)[index - 1],
            "ending_noa": (108.0, 116.0)[index - 1],
        }
        ids = {concept: f"assumption:penman:forecast:y{index}:{concept}" for concept in values}
        for concept, value in values.items():
            assumptions.append(
                _assumption(
                    ids[concept],
                    concept=concept,
                    value=value,
                    unit="USD millions",
                    scope="penman",
                    scenario=None,
                )
            )
        penman_forecast.append(
            {
                "period_end": end,
                "sales_assumption_id": ids["sales"],
                "operating_income_assumption_id": ids["operating_income_after_tax"],
                "ending_noa_assumption_id": ids["ending_noa"],
            }
        )

    primary_hurdle_id = "assumption:penman:primary-hurdle"
    assumptions.append(
        _assumption(
            primary_hurdle_id,
            concept="hurdle_rate",
            value=0.10,
            unit="decimal",
            scope="penman",
            scenario=None,
        )
    )
    hurdle_ids = []
    for index, value in enumerate((0.08, 0.10, 0.12)):
        identifier = f"assumption:penman:hurdle:{index}"
        hurdle_ids.append(identifier)
        assumptions.append(
            _assumption(
                identifier,
                concept="hurdle_rate",
                value=value,
                unit="decimal",
                scope="penman",
                scenario=None,
            )
        )
    growth_ids = []
    for index, value in enumerate((-0.02, 0.00, 0.04)):
        identifier = f"assumption:penman:growth:{index}"
        growth_ids.append(identifier)
        assumptions.append(
            _assumption(
                identifier,
                concept="growth_rate",
                value=value,
                unit="decimal",
                scope="penman",
                scenario=None,
            )
        )
    long_run_growth_id = "assumption:penman:long-run-growth"
    assumptions.append(
        _assumption(
            long_run_growth_id,
            concept="growth_rate",
            value=0.02,
            unit="decimal",
            scope="penman",
            scenario=None,
        )
    )
    challenge = []
    for index, (_start, end) in enumerate(CHALLENGE_PERIODS, start=1):
        values = {
            "sales": (145.0, 157.0)[index - 1],
            "ending_noa": (124.0, 131.0)[index - 1],
        }
        ids = {concept: f"assumption:penman:challenge:y{index}:{concept}" for concept in values}
        for concept, value in values.items():
            assumptions.append(
                _assumption(
                    ids[concept],
                    concept=concept,
                    value=value,
                    unit="USD millions",
                    scope="penman",
                    scenario=None,
                )
            )
        challenge.append(
            {
                "period_end": end,
                "sales_assumption_id": ids["sales"],
                "ending_noa_assumption_id": ids["ending_noa"],
            }
        )

    mckinsey = {
        "base_invested_capital_fact_id": "fact-invested-capital",
        "scenario_payload": {"scenarios": scenarios},
    }
    penman = {
        "current_noa_fact_id": "fact-noa",
        "net_financial_obligations_fact_id": "fact-nfo",
        "penman_payload": {
            "primary_hurdle_assumption_id": primary_hurdle_id,
            "hurdle_assumption_ids": hurdle_ids,
            "growth_rate_assumption_ids": growth_ids,
            "long_run_growth_assumption_id": long_run_growth_id,
            "forecast": penman_forecast,
            "market_challenge_path": challenge,
            "include_cap_diagnostic": False,
        },
    }
    assert len([item for item in assumptions if item["scope"] == "mckinsey"]) == 48
    assert len([item for item in assumptions if item["scope"] == "penman"]) == 18
    assumptions.sort(key=lambda item: item["assumption_id"])
    assert all(type(item["value"]) is float for item in assumptions)
    return assumptions, mckinsey, penman


def _kernel_ledger(example: dict[str, Any], *, issuer_id: str) -> dict[str, Any]:
    ledger = copy.deepcopy(example["fact_ledger"])
    ledger["entity_id"] = issuer_id
    ledger["valuation_date"] = "2026-06-30"
    ledger["sources"][0]["published_date"] = "2026-06-30"
    ledger["sources"][0]["retrieved_at"] = "2026-06-30T00:00:00Z"
    removed = {
        "fact-cash",
        "fact-current-common-shares",
        "fact-market-equity",
        "fact-market-price-per-current-common-share",
        "fact-pension",
    }
    ledger["facts"] = [item for item in ledger["facts"] if item["fact_id"] not in removed]
    for item in ledger["facts"]:
        if item["fact_id"] in {"fact-debt", "fact-nfo"}:
            item["value"] = 25
    return ledger


def _bridge_roles() -> list[dict[str, Any]]:
    roles = (
        "nonoperating_asset",
        "debt",
        "debt_equivalent",
        "lease_liability",
        "unfunded_pension",
        "preferred_stock",
        "noncontrolling_interest",
        "option_or_dilution_claim",
        "other_senior_claim",
    )
    return [
        {
            "role": role,
            "status": "modeled" if role == "debt" else "explicitly_absent",
            "fact_id": "fact-debt" if role == "debt" else None,
            "rationale": (
                "The reviewed debt Fact is modeled."
                if role == "debt"
                else f"No reviewed {role} claim enters this standard fixture."
            ),
            "source_fact_ids": (
                ["fact-debt"]
                if role == "debt"
                else ["fact-assets", "fact-liabilities", "fact-revenue"]
            ),
        }
        for role in roles
    ]


def _request_ready_phase5c(existing: dict[str, Any], example: dict[str, Any]) -> dict[str, Any]:
    phase5c = copy.deepcopy(existing)
    bridge = phase5c["equity_bridge_result"]
    bridge["bridge_items"] = [{"item_id": "debt", "fact_id": "fact-debt"}]
    bridge["role_assertions"] = _bridge_roles()
    phase5c["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    phase5c.update(
        {
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
                                "fact_ids": ["fact-liabilities"],
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
                            "total_assets": "fact-assets",
                            "adjusted_total_liabilities": "fact-liabilities",
                            "common_equity": "fact-equity",
                        },
                        "stock_root_fact_ids": {"adjusted_total_liabilities": ["fact-liabilities"]},
                    },
                    "clean_surplus": {
                        "status": "reconciles_independently",
                        "role_fact_ids": {
                            "beginning_common_equity": "fact-beginning-equity",
                            "comprehensive_income_attributable_to_common": (
                                "fact-comprehensive-income"
                            ),
                            "net_distributions_to_owners": "fact-distributions",
                            "ending_common_equity": "fact-ending-equity",
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
                    "value": (
                        None
                        if key == "credible_near_term_earnings"
                        else False
                        if key == "required_data_complete"
                        else True
                    ),
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
        }
    )
    return phase5c


def _request_ready_freeze(
    freeze: PriceBlindFreezeCompilationResult,
    *,
    example: dict[str, Any],
    integer_assumption: bool = False,
) -> PriceBlindFreezeCompilationResult:
    payload = freeze.artifact.to_dict()
    assumptions, mckinsey, penman = _request_ready_method_inputs()
    if integer_assumption:
        integer_candidate = next(
            item
            for item in assumptions
            if item["assumption_id"] == "assumption:mckinsey:base:y1:revenue"
        )
        assert integer_candidate["value"] == 200.0
        integer_candidate["value"] = 200
    ledger = _kernel_ledger(example, issuer_id=payload["issuer_id"])
    assumption_ledger = {
        "schema_version": "1.0.0",
        "fact_ledger_fingerprint": canonical_sha256(ledger),
        "assumptions": assumptions,
    }
    reviewed = payload["reviewed_assumptions"]
    reviewed["augmented_fact_ledger_payload"] = ledger
    reviewed["assumption_ledger_payload"] = assumption_ledger
    reviewed["assumption_entries_sha256"] = canonical_sha256(assumptions)
    payload["phase5c_readiness"] = _request_ready_phase5c(payload["phase5c_readiness"], example)
    payload["mckinsey_inputs"] = mckinsey
    payload["penman_inputs"] = penman
    payload["protected_mckinsey_sha256"] = _protected_mckinsey(payload)
    payload["protected_penman_assumptions_sha256"] = _protected_penman(payload)
    payload.pop("price_blind_input_fingerprint")
    payload["price_blind_input_fingerprint"] = canonical_sha256(payload)
    artifact = PriceBlindInputArtifact(payload)
    handoffs = tuple(
        replace(
            handoff,
            price_blind_input_fingerprint=artifact.fingerprint,
            protected_mckinsey_sha256=artifact.payload["protected_mckinsey_sha256"],
            protected_penman_assumptions_sha256=artifact.payload[
                "protected_penman_assumptions_sha256"
            ],
        )
        if handoff.state in {"price_blind_input_frozen", "market_reference_allowed"}
        else handoff
        for handoff in freeze.handoffs
    )
    return PriceBlindFreezeCompilationResult(
        artifact=artifact,
        handoffs=handoffs,
        candidates=freeze.candidates,
        decisions=freeze.decisions,
        supplemental_reference_closure=freeze.supplemental_reference_closure,
    )


def _kernel_fixture() -> tuple[Path, dict[str, Any]]:
    if PRIVATE_KERNEL_AVAILABLE:
        assert _PRIVATE_KERNEL is not None
        assert _PRIVATE_EXAMPLE is not None
        return _PRIVATE_KERNEL, json.loads(_PRIVATE_EXAMPLE.read_text(encoding="utf-8"))
    return PUBLIC_KERNEL_REPOSITORY, public_kernel_example()


def _compile_pr1_request(
    *,
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kernel: Path,
    example: dict[str, Any],
    integer_assumption: bool = False,
) -> tuple[Any, PriceBlindFreezeCompilationResult]:
    monkeypatch.setattr(
        market_provider_module,
        "_AUTHORIZATION_STATE_BASE",
        tmp_path / "owner-research-state",
    )
    original_governed_graph = market_slice_fixtures.v2_fixtures._governed_graph

    def governed_graph_with_company_identity(*args, **kwargs):
        graph, security = original_governed_graph(*args, **kwargs)
        return _bind_company_identity(graph), security

    monkeypatch.setattr(
        market_slice_fixtures.v2_fixtures,
        "_governed_graph",
        governed_graph_with_company_identity,
    )
    original_rebind = market_slice_fixtures._rebind_freeze_to_phase5c_authority

    def rebind_request_ready(graph, freeze):
        graph, rebound = original_rebind(graph, freeze)
        return graph, _request_ready_freeze(
            rebound,
            example=example,
            integer_assumption=integer_assumption,
        )

    monkeypatch.setattr(
        market_slice_fixtures,
        "_rebind_freeze_to_phase5c_authority",
        rebind_request_ready,
    )
    graph, freeze, directory, security, acquisition, current_shares = (
        market_slice_fixtures._v2_rollforward_inputs(
            sample_payloads,
            monkeypatch,
            tmp_path,
        )
    )
    assert acquisition.access_result.provider_call_count == 1
    prepared = build_reviewed_market_reference_snapshot(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        acquisition=acquisition,
        current_shares=current_shares,
    )
    assert acquisition.access_result.provider_call_count == 1
    artifact = freeze.artifact.payload
    preparation = OwnerValuationPreparationResult(
        status="prepared",
        issuer_id=artifact["issuer_id"],
        data_cutoff_date=artifact["data_cutoff_date"],
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        prepared_market_reference=prepared,
        issue_codes=(),
    )
    compiled = compile_final_valuation_request(
        preparation=preparation,
        expected_freeze=freeze,
        kernel_repository=kernel,
    )
    assert acquisition.access_result.provider_call_count == 1
    return compiled, freeze


def test_compiler_rejects_integer_assumption_before_isolated_execution(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kernel, example = _kernel_fixture()
    compiled, _freeze = _compile_pr1_request(
        sample_payloads=sample_payloads,
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        kernel=kernel,
        example=example,
        integer_assumption=True,
    )

    assert compiled.status == "blocked"
    assert compiled.issue_codes == ("final_request_blocked:FinalRequestCompilationError",)
    assert compiled.request_payload is None
    assert compiled.canonical_request_json is None
    assert compiled.request_sha256 is None


def test_public_request_contract_is_byte_exact_and_private_oracle_runs_when_available(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Diagnostic only; release acceptance requires the isolated runtime test below."""

    kernel, example = _kernel_fixture()
    compiled, _freeze = _compile_pr1_request(
        sample_payloads=sample_payloads,
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        kernel=kernel,
        example=example,
    )
    assert compiled.status == "compiled", compiled.issue_codes
    assert compiled.canonical_request_json is not None
    expected_request_sha256 = (
        EXPECTED_REQUEST_SHA256 if PRIVATE_KERNEL_AVAILABLE else EXPECTED_PUBLIC_REQUEST_SHA256
    )
    assert compiled.request_sha256 == expected_request_sha256
    request_bytes = compiled.canonical_request_json.encode("utf-8")
    request = json.loads(request_bytes)
    assert request_bytes == canonical_json(request).encode("utf-8")
    assert set(request) >= {"mckinsey", "penman"}
    assert "weighted_multi_model_target_price" not in request_bytes.decode("utf-8")
    if not PRIVATE_KERNEL_AVAILABLE:
        return
    script = (
        "import json,sys; from owner_valuation import run_dual_panel; "
        "request=json.loads(sys.stdin.buffer.read()); "
        "result=run_dual_panel(request); "
        "sys.stdout.buffer.write(json.dumps(result,allow_nan=False,ensure_ascii=False,"
        "sort_keys=True,separators=(',',':')).encode('utf-8'))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=request_bytes,
        capture_output=True,
        check=True,
        env={
            "PYTHONPATH": str(kernel / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        timeout=30,
    )
    assert completed.stderr == b""
    assert hashlib.sha256(completed.stdout).hexdigest() == EXPECTED_RESULT_SHA256
    output = json.loads(completed.stdout)
    assert completed.stdout == canonical_json(output).encode("utf-8")
    assert set(output["panels"]) == {"mckinsey", "penman"}
    assert output["routing"]["blocked_methods"] == ["weighted_multi_model_target_price"]
    assert output["decision_protocol"]["keep_panels_separate"] is True


def test_pr1_rollforward_compiles_and_executes_exact_dual_panel_oracle(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = {name: os.environ.get(name) for name in RUNTIME_ENV}
    execution_required = os.environ.get("PHASE5_V1_KERNEL_EXECUTION_REQUIRED")
    runtime_supplied = tuple(bool(runtime[name]) for name in RUNTIME_ENV)
    if any(runtime_supplied) and not all(runtime_supplied):
        pytest.fail("partial pinned-kernel runtime authority is forbidden")
    if execution_required not in {None, "0", "1"}:
        pytest.fail("PHASE5_V1_KERNEL_EXECUTION_REQUIRED must be exactly 0 or 1")
    if execution_required == "1" and not all(runtime_supplied):
        pytest.fail("required release execution has no complete pinned-kernel runtime")
    if execution_required == "1" and not PRIVATE_KERNEL_AVAILABLE:
        pytest.fail("required release execution has no private kernel checkout")
    if execution_required != "1" and any(runtime_supplied):
        pytest.fail("pinned-kernel runtime was supplied outside the authorized execution job")
    kernel, example = _kernel_fixture()
    compiled, freeze = _compile_pr1_request(
        sample_payloads=sample_payloads,
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        kernel=kernel,
        example=example,
    )
    artifact = freeze.artifact.payload
    assumption_bytes_before = canonical_json(
        artifact["reviewed_assumptions"]["assumption_ledger_payload"]["assumptions"]
    ).encode("utf-8")
    assert compiled.status == "compiled", compiled.issue_codes
    assert compiled.request_payload is not None
    assert compiled.fact_ledger_result is not None
    assert compiled.assumption_ledger_result is not None
    assert compiled.canonical_request_json is not None
    request = compiled.request_payload

    assert request["company"]["name"] == COMPANY_NAME
    assert request["company"]["name"] != compiled.issuer_id
    assert compiled.company_legal_name_value == COMPANY_NAME
    assert compiled.company_name_fact_id == COMPANY_NAME_FACT_ID
    assert compiled.company_name_source_document_id == COMPANY_NAME_SOURCE_ID
    assert all(
        len(value) == 64
        for value in (
            compiled.company_name_fact_fingerprint,
            compiled.company_name_source_document_fingerprint,
            compiled.company_identity_binding_sha256,
        )
    )

    assert tuple(
        row["period_end"] for row in request["mckinsey"]["scenarios"][0]["forecast"]
    ) == tuple(end for _start, end in FORECAST_PERIODS)
    assert tuple(row["period_end"] for row in request["penman"]["forecast"]) == tuple(
        end for _start, end in FORECAST_PERIODS
    )
    assert tuple(row["period_end"] for row in request["penman"]["market_challenge_path"]) == tuple(
        end for _start, end in CHALLENGE_PERIODS
    )
    anchor = date.fromisoformat(compiled.valuation_date)
    assert FORECAST_PERIODS == (
        ((anchor + timedelta(days=1)).isoformat(), "2027-06-30"),
        ("2027-07-01", "2028-06-30"),
    )
    assert CHALLENGE_PERIODS == (
        ("2028-07-01", "2029-06-30"),
        ("2029-07-01", "2030-06-30"),
    )

    projection = compiled.fact_ledger_result.current_share_projection
    assert projection.status == "eligible"
    assert projection.evidence_kind == "completed_event_rollforward"
    assert projection.current_share_fact_id == ("derived:current-shares:96632f26dd3058892be92854")
    projected_facts = {item["fact_id"]: item for item in projection.facts}
    current = projected_facts[projection.current_share_fact_id]
    assert projected_facts["fact:shares:opening"]["value"] == 100.0
    assert projected_facts["fact:event:2026:0"]["concept"] == ("completed_common_share_repurchase")
    assert projected_facts["fact:event:2026:0"]["value"] == 5.0
    assert current["value"] == 95.0
    assert current["parent_fact_ids"] == (
        "fact:shares:opening",
        "fact:event:2026:0",
    )
    assert "fact:event:2026:1" not in projected_facts
    assert len(projection.arithmetic_steps) == 2
    assert projection.arithmetic_steps[0]["operation"] == "opening"
    event_step = projection.arithmetic_steps[-1]
    assert event_step["operation"] == "subtract"
    assert event_step["representative_fact_id"] == "fact:event:2026:0"
    assert event_step["corroborating_member_fact_ids"] == (
        "fact:event:2026:0",
        "fact:event:2026:1",
    )
    assert event_step["input_binary64_hex"] == "4014000000000000"
    assert event_step["running_output_binary64_hex"] == "4057c00000000000"
    attested = {tuple(item) for item in projection.research_evidence_attestation["objects"]}
    assert any(item[:2] == ("Fact", "fact:event:2026:1") for item in attested)
    witness_by_label = {item.label: item for item in projection.numeric_witnesses}
    assert witness_by_label["share:fact:shares:opening"].binary64_hex == "4059000000000000"
    assert witness_by_label["share:fact:event:2026:0"].binary64_hex == "4014000000000000"
    assert (
        witness_by_label[f"share:{projection.current_share_fact_id}"].binary64_hex
        == "4057c00000000000"
    )

    final_facts = {item["fact_id"]: item for item in request["fact_ledger"]["facts"]}
    final_sources = {item["source_id"]: item for item in request["fact_ledger"]["sources"]}
    quote = next(
        item
        for item in final_facts.values()
        if item["concept"] == "market_price_per_current_common_share"
    )
    market_equity = next(
        item for item in final_facts.values() if item["concept"] == "market_equity_value"
    )
    assert quote["value"] == 50.125
    assert final_sources[quote["source_id"]]["publisher"] == ("provider:human-reviewed-file")
    assert final_sources[quote["source_id"]]["publisher"] != compiled.issuer_id
    fact_result = compiled.fact_ledger_result
    assert fact_result.market_provider_id == ("provider:human-reviewed-file")
    expected_receipt_id = (
        EXPECTED_MARKET_RECEIPT_ID
        if PRIVATE_KERNEL_AVAILABLE
        else EXPECTED_PUBLIC_MARKET_RECEIPT_ID
    )
    expected_receipt_fingerprint = (
        EXPECTED_MARKET_RECEIPT_FINGERPRINT
        if PRIVATE_KERNEL_AVAILABLE
        else EXPECTED_PUBLIC_MARKET_RECEIPT_FINGERPRINT
    )
    assert fact_result.market_provider_receipt_id == expected_receipt_id
    assert fact_result.market_provider_receipt_fingerprint == expected_receipt_fingerprint
    assert (
        fact_result.current_share_compilation_fingerprint
        == (projection.research_evidence_attestation["current_share_compilation_fingerprint"])
    )
    assert fact_result.market_source_document_id == quote["source_id"]
    assert fact_result.market_source_ref_fingerprint == canonical_sha256(
        final_sources[quote["source_id"]]
    )
    assert fact_result.market_quote_fact_id == quote["fact_id"]
    assert fact_result.quote_projection_witness.binary64_hex == "4049100000000000"
    assert market_equity["value"] == 4761.875
    assert market_equity["unit"] == "USD millions"
    assert market_equity["parent_fact_ids"] == (
        quote["fact_id"],
        projection.current_share_fact_id,
    )
    assert market_equity["fact_id"] == f"derived:{fact_result.market_equity_calculation_id}"
    assert fact_result.market_equity_projection_witness.binary64_hex == "40b299e000000000"
    assert all(
        len(value) == 64
        for value in (
            fact_result.market_validation_context_fingerprint,
            fact_result.market_access_result_fingerprint,
            fact_result.market_source_document_fingerprint,
            fact_result.market_quote_fact_fingerprint,
            fact_result.market_equity_calculation_fingerprint,
            fact_result.market_evidence_binding_sha256,
        )
    )
    assert request["mckinsey"]["equity_bridge"]["share_denominator_fact_id"] == (
        projection.current_share_fact_id
    )
    assert request["penman"]["market_equity_value_fact_id"] == market_equity["fact_id"]
    assert (
        canonical_json(request["assumption_ledger"]["assumptions"]).encode("utf-8")
        == assumption_bytes_before
    )
    assert (
        compiled.assumption_ledger_result.assumption_entries_sha256
        == hashlib.sha256(assumption_bytes_before).hexdigest()
    )

    request_bytes = compiled.canonical_request_json.encode("utf-8")
    assert request_bytes == canonical_json(request).encode("utf-8")
    expected_request_sha256 = (
        EXPECTED_REQUEST_SHA256 if PRIVATE_KERNEL_AVAILABLE else EXPECTED_PUBLIC_REQUEST_SHA256
    )
    assert compiled.request_sha256 == expected_request_sha256
    if execution_required != "1":
        return
    runtime_manifest = Path(runtime["OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST"])
    runtime_manifest_bytes = runtime_manifest.read_bytes()
    manifest = json.loads(runtime_manifest_bytes)
    attestation_details = TRUSTED_CONTAINER_ATTESTATION.lstat()
    assert stat.S_ISREG(attestation_details.st_mode)
    assert attestation_details.st_uid == 0
    assert attestation_details.st_gid == 0
    assert stat.S_IMODE(attestation_details.st_mode) == 0o444
    assert attestation_details.st_nlink == 1
    attestation_bytes = TRUSTED_CONTAINER_ATTESTATION.read_bytes()
    attestation = json.loads(attestation_bytes)
    assert runtime_manifest_bytes == canonical_json(manifest).encode("utf-8")
    assert attestation_bytes == canonical_json(attestation).encode("utf-8")
    assert (
        hashlib.sha256(runtime_manifest_bytes).hexdigest()
        == (runtime["OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST_FILE_SHA256"])
    )
    assert (
        hashlib.sha256(attestation_bytes).hexdigest()
        == (runtime["OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256"])
    )
    assert manifest["kernel"]["wheel_sha256"] == EXPECTED_KERNEL_WHEEL_SHA256
    assert manifest["authority"]["sha256"] == EXPECTED_RUNTIME_AUTHORITY_SHA256
    assert manifest["producer"]["materializer_sha256"] == EXPECTED_MATERIALIZER_SHA256
    assert manifest["producer"]["runner_sha256"] == EXPECTED_RUNNER_SHA256
    assert manifest["result_schema"]["sha256"] == EXPECTED_RESULT_SCHEMA_SHA256
    assert canonical_sha256(manifest["wheels"]) == EXPECTED_WHEEL_INVENTORY_SHA256
    assert manifest["container"]["image_reference"] == EXPECTED_CONTAINER_IMAGE
    assert manifest["container"]["image_manifest_digest"] == EXPECTED_CONTAINER_MANIFEST_DIGEST
    assert manifest["container"]["image_config_digest"] == EXPECTED_CONTAINER_CONFIG_DIGEST
    assert manifest["container"]["platform"] == "linux/amd64"
    assert manifest["container"]["python_patch"] == "3.11.15"
    assert manifest["container"]["network_mode"] == "none"
    assert manifest["container"]["read_only_rootfs"] is True
    assert manifest["container"]["pull_policy"] == "never"
    assert manifest["container"]["cap_drop"] == ["ALL"]
    assert manifest["container"]["security_opt"] == ["no-new-privileges:true"]
    assert manifest["trusted_workflow"] == {
        "attestation_mount_target": "/run/owner-research",
        "attestation_path": str(TRUSTED_CONTAINER_ATTESTATION),
        "attestation_sha256_env": ("OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256"),
        "read_only_mounts": EXPECTED_WORKFLOW_READ_ONLY_MOUNTS,
        "writable_mounts": EXPECTED_WORKFLOW_WRITABLE_MOUNTS,
    }
    assert set(attestation) == {
        "schema_version",
        "authority_kind",
        "image_reference",
        "image_manifest_digest",
        "image_config_digest",
        "platform",
        "python_patch",
        "security_profile",
        "security_profile_sha256",
    }
    assert attestation["schema_version"] == "1.0.0"
    assert attestation["authority_kind"] == "trusted_workflow_container"
    assert attestation["image_reference"] == EXPECTED_CONTAINER_IMAGE
    assert attestation["image_manifest_digest"] == EXPECTED_CONTAINER_MANIFEST_DIGEST
    assert attestation["image_config_digest"] == EXPECTED_CONTAINER_CONFIG_DIGEST
    assert attestation["platform"] == "linux/amd64"
    assert attestation["python_patch"] == "3.11.15"
    uid, gid = os.getuid(), os.getgid()
    assert uid > 0
    assert gid > 0
    assert attestation["security_profile"] == {
        "boundary": "trusted_workflow_authorized_container",
        "cap_drop": ["ALL"],
        "cpu_limit": "1.0",
        "memory_limit_bytes": 1610612736,
        "memory_swap_limit_bytes": 1610612736,
        "network_mode": "none",
        "pids_limit": 64,
        "pull_policy": "never",
        "read_only_mounts": EXPECTED_WORKFLOW_READ_ONLY_MOUNTS,
        "read_only_rootfs": True,
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": ["/tmp:rw,exec,nosuid,nodev,size=268435456,mode=1777"],
        "ulimits": ["core=0:0", "fsize=67108864:67108864", "nofile=64:64"],
        "user": f"{uid}:{gid}",
        "writable_mounts": EXPECTED_WORKFLOW_WRITABLE_MOUNTS,
    }
    assert attestation["security_profile_sha256"] == canonical_sha256(
        attestation["security_profile"]
    )
    assert not Path("/usr/bin/docker").exists()
    assert not Path("/var/run/docker.sock").exists()
    assert not any(name.startswith("DOCKER_") for name in os.environ)

    execution = execute_in_authorized_container(
        request_bytes,
        runtime_manifest=runtime_manifest,
        runtime_manifest_file_sha256=runtime["OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST_FILE_SHA256"],
        cas_root=Path(runtime["OWNER_RESEARCH_KERNEL_CAS"]),
    )
    assert execution.execution_boundary == "trusted_workflow_authorized_container"
    assert execution.kernel_call_count == 1
    assert execution.kernel_wheel_sha256 == EXPECTED_KERNEL_WHEEL_SHA256
    assert execution.runner_sha256 == EXPECTED_RUNNER_SHA256
    assert (
        execution.runtime_manifest_file_sha256
        == runtime["OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST_FILE_SHA256"]
    )
    assert len(execution.runtime_manifest_file_sha256) == 64
    assert execution.runtime_authority_sha256 == EXPECTED_RUNTIME_AUTHORITY_SHA256
    assert execution.runtime_manifest_fingerprint == manifest["manifest_fingerprint"]
    assert len(execution.runtime_manifest_fingerprint) == 64
    assert execution.result_schema_sha256 == EXPECTED_RESULT_SCHEMA_SHA256
    assert execution.wheel_inventory_sha256 == EXPECTED_WHEEL_INVENTORY_SHA256
    assert execution.docker_executable_sha256 is None
    assert execution.container_identity_sha256 is None
    assert execution.docker_image_inspect_sha256 is None
    assert execution.container_image_reference == EXPECTED_CONTAINER_IMAGE
    assert execution.container_image_manifest_digest == EXPECTED_CONTAINER_MANIFEST_DIGEST
    assert execution.container_image_config_digest == EXPECTED_CONTAINER_CONFIG_DIGEST
    assert execution.container_platform == "linux/amd64"
    assert execution.container_security_profile_sha256 == (attestation["security_profile_sha256"])
    assert (
        execution.trusted_workflow_attestation_sha256
        == (runtime["OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256"])
    )
    assert execution.request_sha256 == EXPECTED_REQUEST_SHA256
    assert execution.request_sha256 == hashlib.sha256(request_bytes).hexdigest()
    assert execution.result_sha256 == EXPECTED_RESULT_SHA256
    assert execution.result_sha256 == hashlib.sha256(execution.result_bytes).hexdigest()
    result_bytes = execution.result_bytes

    output = json.loads(result_bytes)
    assert result_bytes == canonical_json(output).encode("utf-8")
    assert output["fact_ledger_fingerprint"] == canonical_sha256(request["fact_ledger"])
    assert output["assumption_ledger_fingerprint"] == canonical_sha256(request["assumption_ledger"])
    assert output["model_input_fingerprint"] == compiled.request_sha256
    assert execution.fact_ledger_fingerprint == output["fact_ledger_fingerprint"]
    assert execution.assumption_ledger_fingerprint == output["assumption_ledger_fingerprint"]
    assert execution.model_input_fingerprint == output["model_input_fingerprint"]
    assert set(output["panels"]) == {"mckinsey", "penman"}
    assert output["routing"]["status"] == "core_supported"
    assert output["routing"]["blocked_methods"] == ["weighted_multi_model_target_price"]
    assert output["decision_protocol"]["keep_panels_separate"] is True
    assert output["accounting_validation"]["balance_sheet_status"] == ("reconciles_independently")
    assert output["accounting_validation"]["clean_surplus_status"] == ("reconciles_independently")
    assert output["accounting_validation"]["quality_gate"]["status"] == "pass"
    assert output["equity_bridge_validation"]["status"] == "complete"
    assert output["equity_bridge_validation"]["modeled_roles"] == ["debt"]

    mckinsey = output["panels"]["mckinsey"]
    assert mckinsey["scenario_value_per_share_range"] == {
        "low": 5.000000000000003,
        "high": 5.000000000000003,
    }
    assert [item["name"] for item in mckinsey["scenarios"]] == list(SCENARIOS)
    for scenario in mckinsey["scenarios"]:
        dcf = scenario["enterprise_dcf"]
        economic_profit = scenario["economic_profit"]
        bridge = scenario["equity_bridge"]
        assert dcf["explicit_free_cash_flows"] == [10.0, 11.0]
        assert dcf["explicit_present_value"] == 17.69770408163265
        assert dcf["terminal_nopat_next"] == 24.200000000000003
        assert dcf["terminal_value_at_horizon"] == 605.0000000000003
        assert dcf["operating_value"] == 500.0000000000002
        assert economic_profit["explicit_economic_profits"] == [8.0, 8.8]
        assert economic_profit["continuing_value_at_horizon"] == 484.0000000000004
        assert economic_profit["operating_value"] == 500.0000000000002
        assert scenario["dcf_ep_reconciliation_difference"] == 0.0
        assert bridge["equity_value"] == 475.0000000000002
        assert bridge["share_denominator"] == 95.0
        assert bridge["value_per_share"] == 5.000000000000003

    penman = output["panels"]["penman"]
    assert penman["accounting_anchor"]["residual_operating_incomes"] == [8.0, 9.0]
    assert penman["accounting_anchor"]["operating_anchor"] == 189.09090909090907
    assert penman["accounting_anchor"]["equity_anchor"] == 164.09090909090907
    assert penman["speculative_value"] == 4597.784090909091
    assert penman["speculative_share_of_market_price"] == 0.9655406937202449
    assert penman["reverse_price"]["implied_growth"] == 0.09825159966488994
    assert penman["reverse_price"]["reconstructed_market_equity_value"] == (4761.8750000000055)
    assert penman["reverse_price"]["round_trip_error"] == 5.4569682106375694e-12
    assert penman["reverse_fade"]["implied_fade_weight"] == 0.9976569105476132
    assert penman["reverse_fade"]["reconstructed_market_equity_value"] == (4761.875000011335)
    assert penman["reverse_fade"]["round_trip_error"] == 1.1335032468196005e-08
    assert penman["cap_diagnostic"] is None
