from __future__ import annotations

import copy

import pytest
from jsonschema import ValidationError

from owner_research.calculation_integrity import build_calculation_result
from owner_research.contracts import contract_from_dict
from owner_research.validation import ContractGraph, ContractGraphError


def _graph(payloads: dict[str, dict]) -> ContractGraph:
    return ContractGraph(
        documents=(contract_from_dict("source-document", payloads["source-document"]),),
        facts=(contract_from_dict("fact", payloads["fact"]),),
        claims=(contract_from_dict("claim", payloads["claim"]),),
        assumptions=(contract_from_dict("assumption", payloads["assumption"]),),
        calculations=(
            contract_from_dict("calculation-result", payloads["calculation-result"]),
        ),
        scores=(contract_from_dict("score", payloads["score"]),),
        manifests=(contract_from_dict("run-manifest", payloads["run-manifest"]),),
    )


def test_valid_graph_has_no_dangling_references(sample_payloads: dict[str, dict]) -> None:
    _graph(sample_payloads).validate()


def test_contract_graph_deep_freezes_and_checks_domain_types(
    sample_payloads: dict[str, dict],
) -> None:
    assumption = contract_from_dict("assumption", sample_payloads["assumption"])
    mutable = [assumption]
    graph = ContractGraph(facts=mutable)  # type: ignore[arg-type]
    mutable.clear()
    assert len(graph.facts) == 1
    with pytest.raises(ContractGraphError, match="Fact domain contains Assumption"):
        graph.validate()


def test_graph_requires_one_issuer(sample_payloads: dict[str, dict]) -> None:
    invalid = copy.deepcopy(sample_payloads)
    invalid["claim"]["issuer_id"] = "issuer:other"
    with pytest.raises(ContractGraphError, match="multiple issuers"):
        _graph(invalid).validate()


def test_dangling_reference_is_rejected(sample_payloads: dict[str, dict]) -> None:
    invalid = copy.deepcopy(sample_payloads)
    invalid["claim"]["supporting_fact_ids"] = ["fact:missing"]
    with pytest.raises(ContractGraphError, match="dangling"):
        _graph(invalid).validate()


def test_fact_dependency_cycle_is_rejected(sample_payloads: dict[str, dict]) -> None:
    doc = contract_from_dict("source-document", sample_payloads["source-document"])
    left = copy.deepcopy(sample_payloads["fact"])
    left["fact_id"] = "fact:left"
    left["parent_fact_ids"] = ["fact:right"]
    left["derivation"] = "Depends on right."
    right = copy.deepcopy(sample_payloads["fact"])
    right["fact_id"] = "fact:right"
    right["parent_fact_ids"] = ["fact:left"]
    right["derivation"] = "Depends on left."
    graph = ContractGraph(
        documents=(doc,),
        facts=(contract_from_dict("fact", left), contract_from_dict("fact", right)),
    )
    with pytest.raises(ContractGraphError, match="Fact dependency cycle"):
        graph.validate()


def test_calculation_dependency_cycle_is_rejected(sample_payloads: dict[str, dict]) -> None:
    left = copy.deepcopy(sample_payloads["calculation-result"])
    left["calculation_id"] = "calc:left"
    left["input_fact_ids"] = []
    left["input_assumption_ids"] = []
    left["input_calculation_ids"] = ["calc:right"]
    left["input_period_ids"] = []
    left["input_bindings"] = {"dependency": "calc:right"}
    right = copy.deepcopy(left)
    right["calculation_id"] = "calc:right"
    right["input_calculation_ids"] = ["calc:left"]
    right["input_bindings"] = {"dependency": "calc:left"}
    graph = ContractGraph(
        calculations=(
            contract_from_dict("calculation-result", left),
            contract_from_dict("calculation-result", right),
        )
    )
    with pytest.raises(ContractGraphError, match="CalculationResult dependency cycle"):
        graph.validate()


def test_ids_cannot_cross_contract_domains(sample_payloads: dict[str, dict]) -> None:
    invalid = copy.deepcopy(sample_payloads)
    invalid["claim"]["claim_id"] = invalid["fact"]["fact_id"]
    with pytest.raises(ContractGraphError, match="multiple contract domains"):
        _graph(invalid).validate()


def test_prior_reports_remain_quarantined_before_freeze(sample_payloads: dict[str, dict]) -> None:
    invalid = copy.deepcopy(sample_payloads)
    invalid["run-manifest"]["anti_anchoring"]["prior_materials_accessed"] = [
        "prior-report:acme:2025"
    ]
    with pytest.raises((ContractGraphError, ValidationError)):
        _graph(invalid).validate()


def test_prior_reports_allowed_only_in_comparison_after_freeze(
    sample_payloads: dict[str, dict],
) -> None:
    valid = copy.deepcopy(sample_payloads)
    anti = valid["run-manifest"]["anti_anchoring"]
    anti["state"] = "comparison"
    anti["conclusion_frozen_at"] = "2026-02-16T02:15:00Z"
    anti["current_conclusion_sha256"] = "1" * 64
    anti["prior_materials_accessed"] = ["prior-report:acme:2025"]
    _graph(valid).validate()


def test_calculations_are_deterministic_program_outputs(sample_payloads: dict[str, dict]) -> None:
    invalid = copy.deepcopy(sample_payloads["calculation-result"])
    invalid["generator"] = "language_model"
    with pytest.raises(ValidationError):
        contract_from_dict("calculation-result", invalid)


def test_supported_calculation_builder_recomputes_integrity(
    sample_payloads: dict[str, dict],
) -> None:
    fact = contract_from_dict("fact", sample_payloads["fact"])
    assumption = contract_from_dict("assumption", sample_payloads["assumption"])
    payload = copy.deepcopy(sample_payloads["calculation-result"])
    payload["input_fingerprint"] = "9" * 64
    payload["output_fingerprint"] = "9" * 64
    result = build_calculation_result(
        payload,
        facts={fact.fact_id: fact},
        assumptions={assumption.assumption_id: assumption},
        calculations={},
    )
    assert result.input_fingerprint != "9" * 64
    assert result.output_fingerprint != "9" * 64


@pytest.mark.parametrize("field", ["input_fingerprint", "output_fingerprint"])
def test_calculation_fingerprints_are_recomputed(
    field: str, sample_payloads: dict[str, dict]
) -> None:
    invalid = copy.deepcopy(sample_payloads)
    invalid["calculation-result"][field] = "9" * 64
    with pytest.raises(ContractGraphError, match=field):
        _graph(invalid).validate()


@pytest.mark.parametrize("failure", ["hash", "missing", "future", "component"])
def test_run_manifest_locks_cutoff_and_inputs(
    failure: str, sample_payloads: dict[str, dict]
) -> None:
    invalid = copy.deepcopy(sample_payloads)
    if failure == "hash":
        invalid["run-manifest"]["input_document_hashes"]["doc:acme:2025-10k"] = "9" * 64
    elif failure == "missing":
        invalid["run-manifest"]["input_document_hashes"] = {}
    elif failure == "future":
        invalid["source-document"]["published_date"] = "2026-02-16"
    else:
        invalid["run-manifest"]["component_lock_sha256"] = "9" * 64
    with pytest.raises(ContractGraphError):
        _graph(invalid).validate()
