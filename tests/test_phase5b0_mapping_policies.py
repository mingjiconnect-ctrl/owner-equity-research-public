from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from owner_research.fingerprints import FrozenMap
from owner_research.schema_store import SCHEMA_NAMES
from owner_research.valuation_fact_mapping_policies import (
    CALCULATION_POLICIES,
    CLASSIFICATION_POLICY_ID,
    CLASSIFICATION_POLICY_VERSION,
    CONCEPT_POLICIES,
    MAPPING_POLICY_ID,
    MAPPING_POLICY_VERSION,
    PERIOD_POLICIES,
    PINNED_FACT_LEDGER_SCHEMA_SHA256,
    READINESS_POLICY_ID,
    READINESS_POLICY_VERSION,
    SOURCE_POLICIES,
    UNIT_POLICIES,
    calculation_policy,
    concept_policy,
    mapping_policy_sha256,
    period_policy,
    readiness_policy_sha256,
    source_policy,
    unit_policy,
)
from owner_research.valuation_fact_mapping_types import (
    CompanyClassificationResult,
    FactLedgerMappingResult,
    FactMappingDecision,
    MethodReadiness,
    ValuationReadinessResult,
)

ROOT = Path(__file__).parents[1]


def _readiness(method: str) -> MethodReadiness:
    return MethodReadiness(
        method=method,
        status="partial",
        required_roles=("revenue", "capital"),
        satisfied_roles=("revenue",),
        missing_roles=("capital",),
        evidence_fact_ids=("fact:revenue",),
        research_evidence_ids=("review:quality",),
        reason_codes=("required_role_missing",),
    )


def test_phase5b0_keeps_43_public_schemas_and_closed_policy_identity() -> None:
    assert len(SCHEMA_NAMES) == 43
    assert MAPPING_POLICY_ID == "research-to-kernel-fact-mapping"
    assert MAPPING_POLICY_VERSION == "1.0.0"
    assert PINNED_FACT_LEDGER_SCHEMA_SHA256 == (
        "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
    )
    assert len(mapping_policy_sha256()) == 64


def test_all_five_mapping_registries_are_closed() -> None:
    assert set(SOURCE_POLICIES) == {"primary_regulatory", "company_primary"}
    assert {"revenue", "invested_capital", "net_operating_assets"}.issubset(
        CONCEPT_POLICIES
    )
    assert set(PERIOD_POLICIES) == {"stock", "flow"}
    assert "currency_per_share" in UNIT_POLICIES
    assert UNIT_POLICIES["currency_per_share"].price_blind_eligible is False
    assert set(CALCULATION_POLICIES) == {
        ("owner-research-quarterly", "0.2.0-alpha.1")
    }
    with pytest.raises(KeyError):
        source_policy("secondary")
    with pytest.raises(KeyError):
        concept_policy("revenues")
    with pytest.raises(KeyError):
        unit_policy("USD")
    with pytest.raises(KeyError):
        period_policy("publication_date")
    with pytest.raises(KeyError):
        calculation_policy("owner-research-dcf", "1.0.0")


def test_internal_mapping_and_readiness_types_are_frozen_and_stable() -> None:
    decision = FactMappingDecision(
        object_type="Fact",
        object_id="fact:revenue",
        disposition="mapped",
        reason_codes=(),
        output_id="fact:revenue",
    )
    mapping = FactLedgerMappingResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        research_bundle_id="bundle:fixture",
        research_bundle_fingerprint="a" * 64,
        dependency_closure_sha256="b" * 64,
        component_lock_sha256="c" * 64,
        mapping_policy_id=MAPPING_POLICY_ID,
        mapping_policy_version=MAPPING_POLICY_VERSION,
        mapping_policy_sha256=mapping_policy_sha256(),
        kernel_fact_ledger_schema_sha256=PINNED_FACT_LEDGER_SCHEMA_SHA256,
        ledger_payload=FrozenMap({"schema_version": "1.0.0", "facts": []}),
        decisions=(decision,),
    )
    classification = CompanyClassificationResult(
        policy_id=CLASSIFICATION_POLICY_ID,
        policy_version=CLASSIFICATION_POLICY_VERSION,
        policy_sha256=readiness_policy_sha256(),
        company_type="nonfinancial_operating_company",
        specialist_route="none",
        research_evidence_ids=("fact:industry",),
        mapped_fact_ids=("fact:revenue",),
        routing_assessments={
            key: {
                "status": "unsatisfied" if key == "required_data_complete" else "blocked",
                "value": False if key == "required_data_complete" else None,
                "rationale": "Synthetic internal routing assessment.",
                "research_evidence_ids": [],
                "mapped_fact_ids": ["fact:revenue"],
                "reason_codes": ["required_role_missing"]
                if key == "required_data_complete"
                else ["phase5c_confirmation_pending"],
            }
            for key in (
                "required_data_complete",
                "stable_capital_structure",
                "operating_financing_separable",
                "credible_noa",
                "credible_near_term_earnings",
                "equity_bridge_complete",
            )
        },
        rationale="Official evidence identifies a general nonfinancial issuer.",
    )
    result = ValuationReadinessResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        mapping_result_fingerprint=mapping.fingerprint,
        readiness_policy_id=READINESS_POLICY_ID,
        readiness_policy_version=READINESS_POLICY_VERSION,
        readiness_policy_sha256=readiness_policy_sha256(),
        classification=classification,
        mckinsey=_readiness("mckinsey"),
        penman=_readiness("penman"),
        specialist_route="none",
    )
    reordered = FactLedgerMappingResult(
        issuer_id=mapping.issuer_id,
        data_cutoff_date=mapping.data_cutoff_date,
        research_bundle_id=mapping.research_bundle_id,
        research_bundle_fingerprint=mapping.research_bundle_fingerprint,
        dependency_closure_sha256=mapping.dependency_closure_sha256,
        component_lock_sha256=mapping.component_lock_sha256,
        mapping_policy_id=mapping.mapping_policy_id,
        mapping_policy_version=mapping.mapping_policy_version,
        mapping_policy_sha256=mapping.mapping_policy_sha256,
        kernel_fact_ledger_schema_sha256=mapping.kernel_fact_ledger_schema_sha256,
        ledger_payload=FrozenMap({"facts": [], "schema_version": "1.0.0"}),
        decisions=(decision,),
    )
    assert mapping.fingerprint == reordered.fingerprint
    assert len(result.fingerprint) == 64
    with pytest.raises(FrozenInstanceError):
        decision.disposition = "blocked"  # type: ignore[misc]


def test_internal_types_reject_forged_statuses_and_coverage() -> None:
    with pytest.raises(ValueError, match="disposition"):
        FactMappingDecision("Fact", "fact:x", "ready", (), None)
    with pytest.raises(ValueError, match="reason code"):
        FactMappingDecision("Fact", "fact:x", "blocked", ("free_text",), None)
    with pytest.raises(ValueError, match="role coverage"):
        MethodReadiness(
            method="mckinsey",
            status="ready",
            required_roles=("revenue",),
            satisfied_roles=(),
            missing_roles=(),
            evidence_fact_ids=(),
            research_evidence_ids=(),
            reason_codes=(),
        )


def test_adversarial_fixture_covers_phase5b_failure_matrix() -> None:
    payload = json.loads(
        (ROOT / "tests/fixtures/phase5b/adversarial-cases.json").read_text()
    )
    assert payload["policy_id"] == MAPPING_POLICY_ID
    assert len(payload["cases"]) >= 21
    assert {item["failure_id"] for item in payload["cases"]} == {
        f"P5-F{number:03d}" for number in range(1, 15)
    }
