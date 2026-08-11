from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from phase5e2a_support import valid_snapshot_graph

import owner_research.valuation_owner_execution as owner_execution_module
from owner_research.contracts import Fact
from owner_research.fingerprints import (
    canonical_json,
    canonical_sha256,
    freeze,
    to_json_value,
)
from owner_research.valuation_final_request import (
    FinalAssumptionLedgerCompilationResult,
    FinalFactLedgerCompilationResult,
    FinalValuationRequestCompilationResult,
    _company_identity_binding_sha256,
    _governed_market_authority,
    _market_evidence_binding_sha256,
    _market_facts,
    _market_source,
    _validated_prepared_market_context,
)
from owner_research.valuation_kernel_projection import project_current_share_lineage
from owner_research.valuation_market_execution_policies import (
    KERNEL_EXECUTION_POLICY,
    PINNED_KERNEL_CONTAINER_IMAGE_CONFIG_DIGEST,
    PINNED_KERNEL_CONTAINER_IMAGE_MANIFEST_DIGEST,
    PINNED_KERNEL_CONTAINER_IMAGE_REFERENCE,
    PINNED_KERNEL_CONTAINER_PLATFORM,
    PINNED_KERNEL_SCHEMA_SHA256,
)
from owner_research.valuation_market_snapshot import PreparedMarketReference
from owner_research.valuation_owner_execution import (
    OwnerValuationExecutionClock,
    execute_owner_valuation,
)
from owner_research.valuation_owner_preparation import OwnerValuationPreparationResult
from owner_research.valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
)


def _noncompiled(
    preparation: OwnerValuationPreparationResult,
) -> FinalValuationRequestCompilationResult:
    return FinalValuationRequestCompilationResult(
        status=preparation.status,
        issuer_id=preparation.issuer_id,
        valuation_date=preparation.data_cutoff_date,
        price_blind_input_fingerprint=preparation.price_blind_input_fingerprint,
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
        issue_codes=preparation.issue_codes,
    )


@pytest.mark.parametrize("status", ("blocked", "specialist_required"))
def test_noncompiled_path_calls_compiler_once_and_never_runs_or_advances(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    prepared, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    preparation = replace(
        prepared,
        status=status,
        prepared_market_reference=None,
        issue_codes=(f"{status}:fixture",),
    )
    compiled = _noncompiled(preparation)
    compiler_calls: list[dict[str, Any]] = []
    runner_calls: list[object] = []
    handoff_calls: list[object] = []

    def compiler(**kwargs: Any) -> FinalValuationRequestCompilationResult:
        compiler_calls.append(kwargs)
        return compiled

    def runner(*args: object, **kwargs: object) -> object:
        runner_calls.append((args, kwargs))
        raise AssertionError("noncompiled path must not invoke the kernel")

    def handoffs(*args: object, **kwargs: object) -> object:
        handoff_calls.append((args, kwargs))
        raise AssertionError("noncompiled path must not construct execution Handoffs")

    monkeypatch.setattr(owner_execution_module, "compile_final_valuation_request", compiler)
    monkeypatch.setattr(owner_execution_module, "execute_pinned_kernel", runner)
    monkeypatch.setattr(owner_execution_module, "_execution_handoffs", handoffs)
    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/unused/kernel"),
        runtime_manifest=Path("/unused/manifest"),
        runtime_manifest_file_sha256="b" * 64,
        cas_root=Path("/unused/cas"),
        clock=OwnerValuationExecutionClock(
            "2026-07-10T01:00:00Z",
            "2026-07-10T01:00:01Z",
        ),
    )

    assert len(compiler_calls) == 1
    assert compiler_calls[0] == {
        "preparation": preparation,
        "expected_freeze": freeze_result,
        "kernel_repository": Path("/unused/kernel"),
    }
    assert runner_calls == []
    assert handoff_calls == []
    assert result.status == status
    assert result.final_request_result is compiled
    assert result.final_request_receipt is None
    assert result.kernel_execution_result is None
    assert result.kernel_execution_receipt is None
    assert result.execution_handoffs == ()
    assert result.validated_graph is None
    assert result.result_bytes is None
    malicious_freeze = SimpleNamespace(
        result_bytes=b'{"forged":true}',
        call_count=1,
        kernel_call_count=1,
    )
    with pytest.raises(ValueError, match="exact price-blind freeze"):
        replace(result, expected_freeze=malicious_freeze)


def test_untyped_kernel_like_freeze_is_rejected_before_compiler_or_runner(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prepared, _freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    preparation = replace(
        prepared,
        status="blocked",
        prepared_market_reference=None,
        issue_codes=("blocked:fixture",),
    )
    compiler_calls: list[object] = []
    runner_calls: list[object] = []
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **kwargs: compiler_calls.append(kwargs),
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *args, **kwargs: runner_calls.append((args, kwargs)),
    )
    malicious_freeze = SimpleNamespace(
        result_bytes=b'{"forged":true}',
        call_count=1,
        kernel_call_count=1,
    )

    with pytest.raises(ValueError, match="exact price-blind freeze"):
        execute_owner_valuation(
            preparation=preparation,
            expected_freeze=malicious_freeze,  # type: ignore[arg-type]
            kernel_repository=Path("/unused/kernel"),
            runtime_manifest=Path("/unused/manifest"),
            runtime_manifest_file_sha256="b" * 64,
            cas_root=Path("/unused/cas"),
            clock=OwnerValuationExecutionClock(
                "2026-07-10T01:00:00Z",
                "2026-07-10T01:00:01Z",
            ),
        )

    assert compiler_calls == []
    assert runner_calls == []


def _prepared_inputs(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[OwnerValuationPreparationResult, PriceBlindFreezeCompilationResult]:
    monkeypatch.setattr(
        "owner_research.valuation_kernel_projection._source_is_registered",
        lambda _document: True,
    )
    graph, snapshot, context, _access, calculation = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    company_source = graph.documents[0]
    company_fact = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:issuer-legal-name",
        issuer_id=snapshot.issuer_id,
        concept="issuer_legal_name",
        value_type="text",
        value="ACME Corporation",
        unit=None,
        currency=None,
        period={"start": None, "end": snapshot.data_cutoff_date},
        source_document_id=company_source.document_id,
        source_locator="cover:issuer-legal-name",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = replace(graph, facts=(*graph.facts, company_fact))
    graph.validate()
    monkeypatch.setattr(
        owner_execution_module,
        "_governed_company_name",
        lambda _prepared: (company_fact.value, company_fact, company_source),
    )
    source = next(
        item for item in graph.documents if item.document_id == snapshot.quote_source_document_id
    )
    quote = next(item for item in graph.facts if item.fact_id == snapshot.quote_fact_id)
    prepared = PreparedMarketReference(
        snapshot=snapshot,
        market_source=source,
        quote_fact=quote,
        market_equity_calculation=calculation,
        current_shares=context.current_share_compilation_result,
        graph=graph,
    )
    artifact = context.price_blind_artifact
    supplemental = next(
        (
            item
            for item in graph.price_blind_reference_closures
            if item.fingerprint == artifact.payload["supplemental_reference_closure_sha256"]
        ),
        None,
    )
    expected_freeze = PriceBlindFreezeCompilationResult(
        artifact=artifact,
        handoffs=graph.valuation_handoffs,
        candidates=graph.valuation_assumption_candidates,
        decisions=graph.valuation_assumption_review_decisions,
        supplemental_reference_closure=supplemental,
    )
    preparation = OwnerValuationPreparationResult(
        status="prepared",
        issuer_id=artifact.payload["issuer_id"],
        data_cutoff_date=artifact.payload["data_cutoff_date"],
        price_blind_input_fingerprint=artifact.fingerprint,
        prepared_market_reference=prepared,
        issue_codes=(),
    )
    return preparation, expected_freeze


def _compiled(
    preparation: OwnerValuationPreparationResult,
) -> FinalValuationRequestCompilationResult:
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    context = _validated_prepared_market_context(prepared)
    freeze_artifact = context.price_blind_artifact.to_dict()
    reviewed = freeze_artifact["reviewed_assumptions"]
    base_ledger = to_json_value(reviewed["augmented_fact_ledger_payload"])
    base_assumption_ledger = to_json_value(reviewed["assumption_ledger_payload"])
    authority = _governed_market_authority(prepared, context)
    projection = project_current_share_lineage(prepared)
    market_source = _market_source(prepared, authority)
    quote_fact, market_fact, quote_witness, market_witness = _market_facts(
        prepared,
        projection,
        prepared.snapshot.quote_currency,
    )
    current_share_id = projection.current_share_fact_id
    assert current_share_id is not None
    source_index = {item["source_id"]: item for item in base_ledger["sources"]}
    fact_index = {item["fact_id"]: item for item in base_ledger["facts"]}
    base_source_ids = set(source_index)
    base_fact_ids = set(fact_index)
    for item in [
        *(to_json_value(value) for value in projection.sources),
        market_source,
    ]:
        assert item["source_id"] not in source_index or source_index[item["source_id"]] == item
        source_index[item["source_id"]] = item
    for item in [
        *(to_json_value(value) for value in projection.facts),
        quote_fact,
        market_fact,
    ]:
        assert item["fact_id"] not in fact_index or fact_index[item["fact_id"]] == item
        fact_index[item["fact_id"]] = item
    sources = [source_index[key] for key in sorted(source_index)]
    facts = [fact_index[key] for key in sorted(fact_index)]
    fact_ledger = {
        "schema_version": "1.0.0",
        "entity_id": preparation.issuer_id,
        "valuation_date": preparation.data_cutoff_date,
        "reporting_currency": prepared.snapshot.quote_currency,
        "sources": sources,
        "facts": facts,
    }
    final_fact_sha256 = canonical_sha256(fact_ledger)
    assumption_ledger = {
        **base_assumption_ledger,
        "fact_ledger_fingerprint": final_fact_sha256,
    }
    market_evidence_binding = _market_evidence_binding_sha256(
        context_id=authority["context_id"],
        context_fingerprint=authority["context_fingerprint"],
        access_fingerprint=authority["access_fingerprint"],
        provider_id=authority["provider_id"],
        provider_registration_sha256=authority["provider_registration_sha256"],
        receipt_id=authority["receipt_id"],
        receipt_fingerprint=authority["receipt_fingerprint"],
        current_share_compilation_fingerprint=prepared.current_shares.fingerprint,
        source_document_id=prepared.market_source.document_id,
        source_document_fingerprint=prepared.market_source.fingerprint,
        source_ref_fingerprint=canonical_sha256(market_source),
        raw_response_sha256=authority["raw_response_sha256"],
        quote_fact_id=prepared.quote_fact.fact_id,
        quote_fact_fingerprint=prepared.quote_fact.fingerprint,
        calculation_id=prepared.market_equity_calculation.calculation_id,
        calculation_fingerprint=prepared.market_equity_calculation.fingerprint,
    )
    fact_result = FinalFactLedgerCompilationResult(
        policy_id="price-blind-final-request",
        policy_version="2.0.0",
        base_ledger_sha256=canonical_sha256(base_ledger),
        base_ledger_payload=freeze(base_ledger),
        base_source_fingerprints=tuple(
            sorted(
                (item["source_id"], canonical_sha256(item))
                for item in base_ledger["sources"]
            )
        ),
        base_fact_fingerprints=tuple(
            sorted(
                (item["fact_id"], canonical_sha256(item))
                for item in base_ledger["facts"]
            )
        ),
        current_share_projection=projection,
        quote_projection_witness=quote_witness,
        market_equity_projection_witness=market_witness,
        market_provider_id=authority["provider_id"],
        market_provider_receipt_id=authority["receipt_id"],
        market_provider_receipt_fingerprint=authority["receipt_fingerprint"],
        market_provider_registration_sha256=authority["provider_registration_sha256"],
        market_validation_context_id=authority["context_id"],
        market_validation_context_fingerprint=authority["context_fingerprint"],
        market_access_result_fingerprint=authority["access_fingerprint"],
        current_share_compilation_fingerprint=prepared.current_shares.fingerprint,
        market_source_document_id=prepared.market_source.document_id,
        market_source_document_fingerprint=prepared.market_source.fingerprint,
        market_source_ref_fingerprint=canonical_sha256(market_source),
        market_raw_response_sha256=authority["raw_response_sha256"],
        market_quote_fact_id=prepared.quote_fact.fact_id,
        market_quote_fact_fingerprint=prepared.quote_fact.fingerprint,
        market_equity_calculation_id=prepared.market_equity_calculation.calculation_id,
        market_equity_calculation_fingerprint=prepared.market_equity_calculation.fingerprint,
        market_evidence_binding_sha256=market_evidence_binding,
        added_source_ids=tuple(
            item["source_id"] for item in sources if item["source_id"] not in base_source_ids
        ),
        added_fact_ids=tuple(
            item["fact_id"] for item in facts if item["fact_id"] not in base_fact_ids
        ),
        fact_ledger_payload=freeze(fact_ledger),
    )
    assumption_result = FinalAssumptionLedgerCompilationResult(
        assumption_entries_sha256=reviewed["assumption_entries_sha256"],
        prior_fact_ledger_fingerprint=fact_result.base_ledger_sha256,
        final_fact_ledger_fingerprint=final_fact_sha256,
        assumption_ledger_payload=freeze(assumption_ledger),
    )
    company_legal_name, company_name_fact, company_name_source = (
        owner_execution_module._governed_company_name(prepared)
    )
    company_identity_binding = _company_identity_binding_sha256(
        issuer_id=preparation.issuer_id,
        legal_name=company_legal_name,
        fact_id=company_name_fact.fact_id,
        fact_fingerprint=company_name_fact.fingerprint,
        source_document_id=company_name_source.document_id,
        source_document_fingerprint=company_name_source.fingerprint,
    )
    request = {
        "schema_version": "2.0.0",
        "fact_ledger": fact_ledger,
        "assumption_ledger": assumption_ledger,
        "company": {"name": company_legal_name, "source_fact_ids": []},
        "routing_assessments": {},
        "method_views": {},
        "mckinsey": {"equity_bridge": {"share_denominator_fact_id": current_share_id}},
        "penman": {"market_equity_value_fact_id": market_fact["fact_id"]},
    }
    return FinalValuationRequestCompilationResult(
        status="compiled",
        issuer_id=preparation.issuer_id,
        valuation_date=preparation.data_cutoff_date,
        price_blind_input_fingerprint=preparation.price_blind_input_fingerprint,
        prepared_market_reference_fingerprint=prepared.fingerprint,
        company_legal_name_value=company_legal_name,
        company_name_fact_id=company_name_fact.fact_id,
        company_name_fact_fingerprint=company_name_fact.fingerprint,
        company_name_source_document_id=company_name_source.document_id,
        company_name_source_document_fingerprint=company_name_source.fingerprint,
        company_identity_binding_sha256=company_identity_binding,
        fact_ledger_result=fact_result,
        assumption_ledger_result=assumption_result,
        request_payload=freeze(request),
        canonical_request_json=canonical_json(request),
        request_sha256=canonical_sha256(request),
        issue_codes=(),
    )


def _clock(preparation: OwnerValuationPreparationResult) -> OwnerValuationExecutionClock:
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    authorization = next(
        item
        for item in prepared.graph.valuation_handoffs
        if item.handoff_id == prepared.snapshot.authorization_handoff_id
    )
    allowed = datetime.fromisoformat(authorization.transitioned_at.replace("Z", "+00:00"))
    retrieved = datetime.fromisoformat(
        prepared.snapshot.quote_retrieved_at.replace("Z", "+00:00")
    )
    start = max(allowed, retrieved)
    return OwnerValuationExecutionClock(
        (start + timedelta(microseconds=1)).isoformat(),
        (start + timedelta(microseconds=2)).isoformat(),
    )


def _runner_result(
    compiled: FinalValuationRequestCompilationResult,
    *,
    execution_boundary: str = "trusted_workflow_authorized_container",
) -> SimpleNamespace:
    assert compiled.request_payload is not None
    assert compiled.canonical_request_json is not None
    assert compiled.request_sha256 is not None
    fact_fingerprint = canonical_sha256(compiled.request_payload["fact_ledger"])
    assumption_fingerprint = canonical_sha256(compiled.request_payload["assumption_ledger"])
    result_payload = {
        "assumption_ledger_fingerprint": assumption_fingerprint,
        "fact_ledger_fingerprint": fact_fingerprint,
        "model_input_fingerprint": compiled.request_sha256,
    }
    result_bytes = canonical_json(result_payload).encode("utf-8")
    host_boundary = execution_boundary == "trusted_host_docker_launcher"
    return SimpleNamespace(
        execution_boundary=execution_boundary,
        request_sha256=compiled.request_sha256,
        result_sha256=hashlib.sha256(result_bytes).hexdigest(),
        result_bytes=result_bytes,
        kernel_wheel_sha256=KERNEL_EXECUTION_POLICY.exact_wheel_sha256,
        runtime_authority_sha256="1" * 64,
        runtime_manifest_file_sha256="d" * 64,
        runtime_manifest_fingerprint="2" * 64,
        runner_sha256="3" * 64,
        result_schema_sha256=PINNED_KERNEL_SCHEMA_SHA256["schemas/valuation-result.schema.json"],
        wheel_inventory_sha256="5" * 64,
        docker_executable_sha256="6" * 64 if host_boundary else None,
        container_image_reference=PINNED_KERNEL_CONTAINER_IMAGE_REFERENCE,
        container_image_manifest_digest=PINNED_KERNEL_CONTAINER_IMAGE_MANIFEST_DIGEST,
        container_image_config_digest=PINNED_KERNEL_CONTAINER_IMAGE_CONFIG_DIGEST,
        container_platform=PINNED_KERNEL_CONTAINER_PLATFORM,
        container_identity_sha256="7" * 64 if host_boundary else None,
        docker_image_inspect_sha256="a" * 64 if host_boundary else None,
        container_security_profile_sha256="8" * 64,
        trusted_workflow_attestation_sha256=None if host_boundary else "9" * 64,
        fact_ledger_fingerprint=fact_fingerprint,
        assumption_ledger_fingerprint=assumption_fingerprint,
        model_input_fingerprint=compiled.request_sha256,
        kernel_call_count=1,
    )


def _completed_result(
    *,
    preparation: OwnerValuationPreparationResult,
    freeze_result: PriceBlindFreezeCompilationResult,
    compiled: FinalValuationRequestCompilationResult,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    execution = _runner_result(compiled)
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *_args, **_kwargs: execution,
    )
    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=_clock(preparation),
    )
    assert result.status == "completed"
    return result


def _rebound_final_request_receipt(receipt: Any, **changes: Any) -> Any:
    payload = receipt.to_dict()
    payload.update(changes)
    payload.pop("receipt_id")
    payload["receipt_id"] = (
        f"final-request-receipt:{payload['issuer_id']}:"
        f"{canonical_sha256(payload)[:24]}"
    )
    return type(receipt)(**payload)


def _market_binding(
    fact_result: FinalFactLedgerCompilationResult,
    **changes: str,
) -> str:
    def value(name: str) -> str:
        return changes.get(name, getattr(fact_result, name))

    return _market_evidence_binding_sha256(
        context_id=value("market_validation_context_id"),
        context_fingerprint=value("market_validation_context_fingerprint"),
        access_fingerprint=value("market_access_result_fingerprint"),
        provider_id=value("market_provider_id"),
        provider_registration_sha256=value("market_provider_registration_sha256"),
        receipt_id=value("market_provider_receipt_id"),
        receipt_fingerprint=value("market_provider_receipt_fingerprint"),
        current_share_compilation_fingerprint=value(
            "current_share_compilation_fingerprint"
        ),
        source_document_id=value("market_source_document_id"),
        source_document_fingerprint=value("market_source_document_fingerprint"),
        source_ref_fingerprint=value("market_source_ref_fingerprint"),
        raw_response_sha256=value("market_raw_response_sha256"),
        quote_fact_id=value("market_quote_fact_id"),
        quote_fact_fingerprint=value("market_quote_fact_fingerprint"),
        calculation_id=value("market_equity_calculation_id"),
        calculation_fingerprint=value("market_equity_calculation_fingerprint"),
    )


@pytest.mark.parametrize(
    "execution_boundary",
    (
        "trusted_host_docker_launcher",
        "trusted_workflow_authorized_container",
    ),
)
def test_success_calls_each_stage_once_preserves_stdout_and_adds_only_v5_v6(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    execution_boundary: str,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    compiled = _compiled(preparation)
    execution = _runner_result(compiled, execution_boundary=execution_boundary)
    compiler_calls: list[dict[str, Any]] = []
    runner_calls: list[tuple[bytes, dict[str, Any]]] = []

    def compiler(**kwargs: Any) -> FinalValuationRequestCompilationResult:
        compiler_calls.append(kwargs)
        return compiled

    def runner(request_bytes: bytes, **kwargs: Any) -> SimpleNamespace:
        runner_calls.append((request_bytes, kwargs))
        return execution

    monkeypatch.setattr(owner_execution_module, "compile_final_valuation_request", compiler)
    monkeypatch.setattr(owner_execution_module, "execute_pinned_kernel", runner)
    original_graph = preparation.prepared_market_reference.graph
    original_handoffs = original_graph.valuation_handoffs
    clock = _clock(preparation)
    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=clock,
        timeout_seconds=27,
    )

    assert len(compiler_calls) == 1
    assert compiler_calls[0]["preparation"] is preparation
    assert compiler_calls[0]["expected_freeze"] is freeze_result
    assert len(runner_calls) == 1
    assert runner_calls[0] == (
        compiled.canonical_request_json.encode("utf-8"),
        {
            "runtime_manifest": Path("/runtime/manifest.json"),
            "runtime_manifest_file_sha256": "d" * 64,
            "cas_root": Path("/runtime/cas"),
            "timeout_seconds": 27,
        },
    )
    assert result.status == "completed"
    assert result.result_bytes is execution.result_bytes
    assert hashlib.sha256(result.result_bytes).hexdigest() == execution.result_sha256
    assert result.final_request_receipt is not None
    assert result.final_request_receipt.valuation_request_sha256 == compiled.request_sha256
    assert result.final_request_receipt.company_name_fact_id == compiled.company_name_fact_id
    assert result.final_request_receipt.company_name_source_document_id == (
        compiled.company_name_source_document_id
    )
    assert compiled.fact_ledger_result is not None
    assert result.final_request_receipt.market_provider_id == (
        compiled.fact_ledger_result.market_provider_id
    )
    assert result.final_request_receipt.market_reference_snapshot_id == (
        preparation.prepared_market_reference.snapshot.snapshot_id
    )
    assert result.kernel_execution_receipt is not None
    assert result.kernel_execution_receipt.execution_boundary == execution_boundary
    assert result.kernel_execution_receipt.runtime_authority_sha256 == (
        execution.runtime_authority_sha256
    )
    assert result.kernel_execution_receipt.trusted_workflow_attestation_sha256 == (
        execution.trusted_workflow_attestation_sha256
    )
    assert result.kernel_execution_receipt.docker_image_inspect_sha256 == (
        execution.docker_image_inspect_sha256
    )
    with pytest.raises(
        ValueError,
        match="receipt ID is not deterministic|receipt or Handoff binding changed",
    ):
        replace(
            result,
            kernel_execution_receipt=replace(
                result.kernel_execution_receipt,
                runner_sha256="f" * 64,
            ),
        )
    final_receipt_payload = result.final_request_receipt.to_dict()
    final_receipt_payload["numeric_projection_sha256"] = "f" * 64
    final_receipt_payload.pop("receipt_id")
    final_receipt_payload["receipt_id"] = (
        f"final-request-receipt:{compiled.issuer_id}:"
        f"{canonical_sha256(final_receipt_payload)[:24]}"
    )
    rebound_final_receipt = type(result.final_request_receipt)(
        **final_receipt_payload
    )
    with pytest.raises(ValueError, match="receipt or Handoff binding changed"):
        replace(result, final_request_receipt=rebound_final_receipt)

    kernel_receipt_payload = result.kernel_execution_receipt.to_dict()
    kernel_receipt_payload["runner_sha256"] = "f" * 64
    kernel_receipt_payload.pop("receipt_id")
    kernel_receipt_payload["receipt_id"] = (
        f"kernel-execution-receipt:{canonical_sha256(kernel_receipt_payload)[:24]}"
    )
    rebound_kernel_receipt = type(result.kernel_execution_receipt)(
        **kernel_receipt_payload
    )
    with pytest.raises(ValueError, match="receipt or Handoff binding changed"):
        replace(result, kernel_execution_receipt=rebound_kernel_receipt)

    with pytest.raises(ValueError, match="preparation fingerprint"):
        replace(result, preparation_fingerprint="f" * 64)
    with pytest.raises(ValueError, match="promoted a frozen result"):
        replace(
            result,
            status="blocked",
            kernel_execution_receipt=None,
            execution_handoffs=(),
            validated_graph=None,
            result_bytes=None,
            issue_codes=("fixture_blocked",),
        )
    with pytest.raises(ValueError, match="receipt or Handoff binding changed"):
        replace(result, result_bytes=b"{}")
    request_handoff, result_handoff = result.execution_handoffs
    authorization = freeze_result.handoffs[-1]
    prefix = authorization.handoff_id.removesuffix(":v4")
    assert (request_handoff.handoff_id, result_handoff.handoff_id) == (
        f"{prefix}:v5",
        f"{prefix}:v6",
    )
    assert request_handoff.handoff_version == 5
    assert request_handoff.predecessor_handoff_id == authorization.handoff_id
    assert request_handoff.transitioned_at == clock.request_compiled_at
    assert request_handoff.market_reference_snapshot_id == (
        preparation.prepared_market_reference.snapshot.snapshot_id
    )
    assert request_handoff.valuation_request_sha256 == compiled.request_sha256
    assert request_handoff.valuation_result_sha256 is None
    assert request_handoff.missing_evidence == ()
    assert result_handoff.handoff_version == 6
    assert result_handoff.predecessor_handoff_id == request_handoff.handoff_id
    assert result_handoff.transitioned_at == clock.kernel_result_frozen_at
    assert result_handoff.valuation_result_sha256 == execution.result_sha256
    assert result_handoff.missing_evidence == ()
    assert result.validated_graph is not original_graph
    assert original_graph.valuation_handoffs == original_handoffs
    assert result.validated_graph.valuation_handoffs == (
        *original_handoffs,
        request_handoff,
        result_handoff,
    )
    result.validated_graph.validate()


def test_preflight_timestamp_block_never_calls_runner_or_returns_handoff(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    compiled = _compiled(preparation)
    runner_calls: list[object] = []
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *args, **kwargs: runner_calls.append((args, kwargs)),
    )
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    quote_retrieved_at = prepared.snapshot.quote_retrieved_at
    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=OwnerValuationExecutionClock(
            quote_retrieved_at,
            (
                datetime.fromisoformat(quote_retrieved_at.replace("Z", "+00:00"))
                + timedelta(microseconds=1)
            ).isoformat(),
        ),
    )

    assert result.status == "blocked"
    assert runner_calls == []
    assert result.execution_handoffs == ()
    assert result.validated_graph is None
    assert result.final_request_receipt is None


def test_invalid_runtime_manifest_hash_blocks_before_runner_or_handoff(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    compiled = _compiled(preparation)
    runner_calls: list[object] = []
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *args, **kwargs: runner_calls.append((args, kwargs)),
    )

    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="not-a-sha",
        cas_root=Path("/runtime/cas"),
        clock=_clock(preparation),
    )

    assert result.status == "blocked"
    assert runner_calls == []
    assert result.final_request_receipt is None
    assert result.execution_handoffs == ()
    assert result.validated_graph is None


def test_coordinated_base_ledger_rebinding_blocks_before_runner(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    compiled = _compiled(preparation)
    fact_result = compiled.fact_ledger_result
    assumption_result = compiled.assumption_ledger_result
    assert fact_result is not None and assumption_result is not None
    final_ledger = to_json_value(fact_result.fact_ledger_payload)
    current_share_id = fact_result.current_share_projection.current_share_fact_id
    assert current_share_id is not None
    current_share_fact = next(
        item for item in final_ledger["facts"] if item["fact_id"] == current_share_id
    )
    current_share_source = next(
        item
        for item in final_ledger["sources"]
        if item["source_id"] == current_share_fact["source_id"]
    )
    forged_base = {
        "schema_version": final_ledger["schema_version"],
        "entity_id": final_ledger["entity_id"],
        "valuation_date": final_ledger["valuation_date"],
        "reporting_currency": final_ledger["reporting_currency"],
        "sources": [current_share_source],
        "facts": [current_share_fact],
    }
    forged_base_sha256 = canonical_sha256(forged_base)
    forged_fact_result = replace(
        fact_result,
        base_ledger_sha256=forged_base_sha256,
        base_ledger_payload=freeze(forged_base),
        base_source_fingerprints=(
            (current_share_source["source_id"], canonical_sha256(current_share_source)),
        ),
        base_fact_fingerprints=(
            (current_share_fact["fact_id"], canonical_sha256(current_share_fact)),
        ),
        added_source_ids=tuple(
            item["source_id"]
            for item in final_ledger["sources"]
            if item["source_id"] != current_share_source["source_id"]
        ),
        added_fact_ids=tuple(
            item["fact_id"]
            for item in final_ledger["facts"]
            if item["fact_id"] != current_share_fact["fact_id"]
        ),
    )
    forged_assumption_result = replace(
        assumption_result,
        prior_fact_ledger_fingerprint=forged_base_sha256,
    )
    forged_request = replace(
        compiled,
        fact_ledger_result=forged_fact_result,
        assumption_ledger_result=forged_assumption_result,
    )
    runner_calls: list[object] = []
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: forged_request,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *args, **kwargs: runner_calls.append((args, kwargs)),
    )

    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=_clock(preparation),
    )

    assert result.status == "blocked"
    assert result.issue_codes == (
        "owner_execution_preflight_blocked:OwnerValuationExecutionError",
    )
    assert runner_calls == []
    assert result.final_request_receipt is None
    assert result.execution_handoffs == ()


def test_superseded_and_quarantined_market_run_never_executes(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    old_root = freeze_result.handoffs[0]
    authorization = freeze_result.handoffs[-1]
    replacement_time = datetime.fromisoformat(
        prepared.snapshot.quote_retrieved_at.replace("Z", "+00:00")
    ) + timedelta(seconds=1)
    replacement = replace(
        old_root,
        handoff_id=f"{old_root.handoff_id}:replacement",
        handoff_run_id=f"{old_root.handoff_run_id}:replacement",
        transitioned_at=replacement_time.isoformat(),
        supersedes_handoff_id=authorization.handoff_id,
        quarantined_market_reference_snapshot_ids=(prepared.snapshot.snapshot_id,),
    )
    stale_graph = replace(
        prepared.graph,
        valuation_handoffs=(*prepared.graph.valuation_handoffs, replacement),
    )
    stale_graph.validate()
    stale_preparation = replace(
        preparation,
        prepared_market_reference=replace(prepared, graph=stale_graph),
    )
    compiled = _compiled(stale_preparation)
    runner_calls: list[object] = []
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *args, **kwargs: runner_calls.append((args, kwargs)),
    )
    result = execute_owner_valuation(
        preparation=stale_preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=OwnerValuationExecutionClock(
            (replacement_time + timedelta(microseconds=1)).isoformat(),
            (replacement_time + timedelta(microseconds=2)).isoformat(),
        ),
    )

    assert result.status == "blocked"
    assert runner_calls == []
    assert result.execution_handoffs == ()
    assert result.validated_graph is None


def test_runner_output_binding_failure_is_hash_only_and_never_advances_graph(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    compiled = _compiled(preparation)
    execution = _runner_result(compiled)
    execution.request_sha256 = "e" * 64
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *_args, **_kwargs: execution,
    )
    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=_clock(preparation),
    )

    assert result.status == "blocked"
    assert result.final_request_receipt is not None
    assert result.kernel_execution_result is None
    assert result.kernel_execution_receipt is None
    assert result.execution_handoffs == ()
    assert result.validated_graph is None
    assert result.result_bytes is None
    assert result.quarantined_result_sha256 == hashlib.sha256(execution.result_bytes).hexdigest()
    assert preparation.prepared_market_reference.graph.valuation_handoffs == (
        freeze_result.handoffs
    )


def test_completed_result_rejects_coordinated_request_provenance_rebindings(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    compiled = _compiled(preparation)
    completed = _completed_result(
        preparation=preparation,
        freeze_result=freeze_result,
        compiled=compiled,
        monkeypatch=monkeypatch,
    )
    receipt = completed.final_request_receipt
    fact_result = compiled.fact_ledger_result
    assert receipt is not None and fact_result is not None

    company_fact_fingerprint = "f" * 64
    company_source_fingerprint = "e" * 64
    company_binding = _company_identity_binding_sha256(
        issuer_id=compiled.issuer_id,
        legal_name=compiled.company_legal_name_value,
        fact_id="fact:forged:issuer-legal-name",
        fact_fingerprint=company_fact_fingerprint,
        source_document_id="doc:forged:issuer-legal-name",
        source_document_fingerprint=company_source_fingerprint,
    )
    forged_company = replace(
        compiled,
        company_name_fact_id="fact:forged:issuer-legal-name",
        company_name_fact_fingerprint=company_fact_fingerprint,
        company_name_source_document_id="doc:forged:issuer-legal-name",
        company_name_source_document_fingerprint=company_source_fingerprint,
        company_identity_binding_sha256=company_binding,
    )
    forged_company_receipt = _rebound_final_request_receipt(
        receipt,
        company_name_fact_id=forged_company.company_name_fact_id,
        company_name_fact_fingerprint=company_fact_fingerprint,
        company_name_source_document_id=(forged_company.company_name_source_document_id),
        company_name_source_document_fingerprint=company_source_fingerprint,
        company_identity_binding_sha256=company_binding,
    )
    with pytest.raises(ValueError, match="provenance"):
        replace(
            completed,
            final_request_result=forged_company,
            final_request_receipt=forged_company_receipt,
        )

    registration_sha256 = "f" * 64
    market_binding = _market_binding(
        fact_result,
        market_provider_registration_sha256=registration_sha256,
    )
    forged_market_result = replace(
        fact_result,
        market_provider_registration_sha256=registration_sha256,
        market_evidence_binding_sha256=market_binding,
    )
    forged_market = replace(compiled, fact_ledger_result=forged_market_result)
    forged_market_receipt = _rebound_final_request_receipt(
        receipt,
        market_provider_registration_sha256=registration_sha256,
        market_evidence_binding_sha256=market_binding,
    )
    with pytest.raises(ValueError, match="provenance"):
        replace(
            completed,
            final_request_result=forged_market,
            final_request_receipt=forged_market_receipt,
        )

    current_share_fingerprint = "f" * 64
    projection_attestation = to_json_value(
        fact_result.current_share_projection.research_evidence_attestation
    )
    projection_attestation["current_share_compilation_fingerprint"] = (
        current_share_fingerprint
    )
    forged_projection = replace(
        fact_result.current_share_projection,
        research_evidence_attestation=projection_attestation,
        research_evidence_sha256=canonical_sha256(projection_attestation),
    )
    share_market_binding = _market_binding(
        fact_result,
        current_share_compilation_fingerprint=current_share_fingerprint,
    )
    forged_share_result = replace(
        fact_result,
        current_share_projection=forged_projection,
        current_share_compilation_fingerprint=current_share_fingerprint,
        market_evidence_binding_sha256=share_market_binding,
    )
    forged_share = replace(compiled, fact_ledger_result=forged_share_result)
    forged_share_receipt = _rebound_final_request_receipt(
        receipt,
        current_share_compilation_fingerprint=current_share_fingerprint,
        current_share_projection_sha256=forged_projection.fingerprint,
        market_evidence_binding_sha256=share_market_binding,
    )
    with pytest.raises(ValueError, match="provenance"):
        replace(
            completed,
            final_request_result=forged_share,
            final_request_receipt=forged_share_receipt,
        )

    with pytest.raises(ValueError, match="provenance"):
        replace(
            completed,
            final_request_result=replace(
                compiled,
                prepared_market_reference_fingerprint="f" * 64,
            ),
        )
    with pytest.raises(ValueError, match="provenance"):
        replace(
            completed,
            final_request_result=replace(
                compiled,
                price_blind_input_fingerprint="f" * 64,
            ),
        )


def test_second_active_run_blocks_preflight_and_frozen_result(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    clone_ids = {
        item.handoff_id: f"{item.handoff_id}:parallel" for item in freeze_result.handoffs
    }
    parallel = tuple(
        replace(
            item,
            handoff_id=clone_ids[item.handoff_id],
            handoff_run_id=f"{item.handoff_run_id}:parallel",
            predecessor_handoff_id=(
                clone_ids[item.predecessor_handoff_id]
                if item.predecessor_handoff_id is not None
                else None
            ),
            supersedes_handoff_id=None,
        )
        for item in freeze_result.handoffs
    )
    two_active_graph = replace(
        prepared.graph,
        valuation_handoffs=(*prepared.graph.valuation_handoffs, *parallel),
    )
    two_active_graph.validate()
    two_active_preparation = replace(
        preparation,
        prepared_market_reference=replace(prepared, graph=two_active_graph),
    )
    compiled = _compiled(two_active_preparation)
    runner_calls: list[object] = []
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *args, **kwargs: runner_calls.append((args, kwargs)),
    )
    blocked = execute_owner_valuation(
        preparation=two_active_preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=_clock(two_active_preparation),
    )
    assert blocked.status == "blocked"
    assert runner_calls == []
    assert blocked.kernel_execution_result is None
    assert blocked.execution_handoffs == ()

    completed = _completed_result(
        preparation=preparation,
        freeze_result=freeze_result,
        compiled=_compiled(preparation),
        monkeypatch=monkeypatch,
    )
    assert completed.validated_graph is not None
    forged_overlay = replace(
        two_active_graph,
        valuation_handoffs=(*two_active_graph.valuation_handoffs, *completed.execution_handoffs),
    )
    forged_overlay.validate()
    with pytest.raises(ValueError, match="active authorization run"):
        replace(
            completed,
            preparation=two_active_preparation,
            validated_graph=forged_overlay,
        )


def test_completed_result_rejects_handoff_id_and_time_rebindings(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    preparation, freeze_result = _prepared_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    completed = _completed_result(
        preparation=preparation,
        freeze_result=freeze_result,
        compiled=_compiled(preparation),
        monkeypatch=monkeypatch,
    )
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    request_handoff, result_handoff = completed.execution_handoffs

    rebound_request = replace(
        request_handoff,
        handoff_id=f"{request_handoff.handoff_id}:rebound",
    )
    rebound_result = replace(
        result_handoff,
        handoff_id=f"{result_handoff.handoff_id}:rebound",
        predecessor_handoff_id=rebound_request.handoff_id,
    )
    rebound_graph = replace(
        prepared.graph,
        valuation_handoffs=(
            *prepared.graph.valuation_handoffs,
            rebound_request,
            rebound_result,
        ),
    )
    rebound_graph.validate()
    with pytest.raises(ValueError, match="deterministic Handoff"):
        replace(
            completed,
            execution_handoffs=(rebound_request, rebound_result),
            validated_graph=rebound_graph,
        )

    shifted_request_time = datetime.fromisoformat(
        request_handoff.transitioned_at.replace("Z", "+00:00")
    ) + timedelta(days=1)
    shifted_result_time = datetime.fromisoformat(
        result_handoff.transitioned_at.replace("Z", "+00:00")
    ) + timedelta(days=1)
    shifted_request = replace(request_handoff, transitioned_at=shifted_request_time.isoformat())
    shifted_result = replace(result_handoff, transitioned_at=shifted_result_time.isoformat())
    shifted_graph = replace(
        prepared.graph,
        valuation_handoffs=(
            *prepared.graph.valuation_handoffs,
            shifted_request,
            shifted_result,
        ),
    )
    shifted_graph.validate()
    with pytest.raises(ValueError, match="deterministic Handoff"):
        replace(
            completed,
            execution_handoffs=(shifted_request, shifted_result),
            validated_graph=shifted_graph,
        )

    retrieved = datetime.fromisoformat(
        prepared.snapshot.quote_retrieved_at.replace("Z", "+00:00")
    )
    at_quote_request = replace(
        request_handoff,
        transitioned_at=prepared.snapshot.quote_retrieved_at,
    )
    at_quote_result = replace(
        result_handoff,
        transitioned_at=(retrieved + timedelta(microseconds=1)).isoformat(),
    )
    at_quote_graph = replace(
        prepared.graph,
        valuation_handoffs=(
            *prepared.graph.valuation_handoffs,
            at_quote_request,
            at_quote_result,
        ),
    )
    at_quote_graph.validate()
    with pytest.raises(ValueError, match="follow accepted market evidence"):
        replace(
            completed,
            clock=OwnerValuationExecutionClock(
                at_quote_request.transitioned_at,
                at_quote_result.transitioned_at,
            ),
            execution_handoffs=(at_quote_request, at_quote_result),
            validated_graph=at_quote_graph,
        )
