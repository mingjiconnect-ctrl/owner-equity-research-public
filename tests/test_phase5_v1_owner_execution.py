from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from phase5e2a_support import valid_snapshot_graph

import owner_research.valuation_owner_execution as owner_execution_module
from owner_research.fingerprints import canonical_json, canonical_sha256, freeze
from owner_research.valuation_final_request import (
    FinalAssumptionLedgerCompilationResult,
    FinalFactLedgerCompilationResult,
    FinalValuationRequestCompilationResult,
)
from owner_research.valuation_kernel_projection import (
    CurrentShareKernelProjection,
    KernelNumericProjectionWitness,
)
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
        company_name_fact_id=None,
        company_name_source_document_id=None,
        fact_ledger_result=None,
        assumption_ledger_result=None,
        request_payload=None,
        canonical_request_json=None,
        request_sha256=None,
        issue_codes=preparation.issue_codes,
    )


@pytest.mark.parametrize("status", ("blocked", "specialist_required"))
def test_noncompiled_path_calls_compiler_once_and_never_runs_or_advances(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    preparation = OwnerValuationPreparationResult(
        status=status,
        issuer_id="issuer:test",
        data_cutoff_date="2026-07-10",
        price_blind_input_fingerprint="a" * 64,
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
    freeze_sentinel = object()
    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_sentinel,  # type: ignore[arg-type]
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
        "expected_freeze": freeze_sentinel,
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


def _prepared_inputs(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[OwnerValuationPreparationResult, PriceBlindFreezeCompilationResult]:
    graph, snapshot, context, _access, calculation = valid_snapshot_graph(
        sample_payloads,
        monkeypatch,
        tmp_path,
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
    share_witness = KernelNumericProjectionWitness.compile(
        label="share:fixture",
        authoritative_decimal=Decimal(
            prepared.snapshot.share_basis["current_common_shares_outstanding_decimal"]
        ),
        scale_divisor=Decimal(1_000_000),
    )
    attestation = {"fixture": "compiled-current-share-lineage"}
    projection = CurrentShareKernelProjection(
        status="eligible",
        evidence_kind=prepared.snapshot.share_basis["evidence_kind"],
        current_share_fact_id=prepared.snapshot.share_basis["shares_outstanding_fact_id"],
        sources=({"source_id": "source:fixture:shares"},),
        facts=({"fact_id": prepared.snapshot.share_basis["shares_outstanding_fact_id"]},),
        numeric_witnesses=(share_witness,),
        arithmetic_steps=({"step": 0, "operation": "fixture"},),
        research_evidence_attestation=attestation,
        research_evidence_sha256=canonical_sha256(attestation),
        issue_codes=(),
    )
    quote_witness = KernelNumericProjectionWitness.compile(
        label="quote:fixture",
        authoritative_decimal=Decimal(prepared.snapshot.quote_price_decimal),
    )
    market_witness = KernelNumericProjectionWitness.compile(
        label="market-equity:fixture",
        authoritative_decimal=Decimal(prepared.snapshot.market_equity["value_decimal"]),
        scale_divisor=Decimal(1_000_000),
    )
    current_share_id = projection.current_share_fact_id
    assert current_share_id is not None
    quote_fact_id = "fact:fixture:quote"
    market_fact_id = "fact:fixture:market"
    fact_ledger = {
        "schema_version": "1.0.0",
        "entity_id": preparation.issuer_id,
        "valuation_date": preparation.data_cutoff_date,
        "reporting_currency": prepared.snapshot.quote_currency,
        "sources": [],
        "facts": [
            {
                "fact_id": current_share_id,
                "concept": "common_shares_outstanding",
                "parent_fact_ids": [],
            },
            {
                "fact_id": quote_fact_id,
                "concept": "market_price_per_current_common_share",
                "parent_fact_ids": [],
            },
            {
                "fact_id": market_fact_id,
                "concept": "market_equity_value",
                "parent_fact_ids": [quote_fact_id, current_share_id],
            },
        ],
    }
    final_fact_sha256 = canonical_sha256(fact_ledger)
    assumption_ledger = {
        "schema_version": "1.0.0",
        "fact_ledger_fingerprint": final_fact_sha256,
        "assumptions": [],
    }
    fact_result = FinalFactLedgerCompilationResult(
        policy_id="price-blind-final-request",
        policy_version="2.0.0",
        base_ledger_sha256="a" * 64,
        base_source_fingerprints=(),
        base_fact_fingerprints=(),
        current_share_projection=projection,
        quote_projection_witness=quote_witness,
        market_equity_projection_witness=market_witness,
        market_provider_id="provider:fixture",
        market_provider_receipt_id="market-receipt:fixture",
        market_provider_receipt_fingerprint="b" * 64,
        added_source_ids=("source:fixture:shares", "source:fixture:market"),
        added_fact_ids=(current_share_id, quote_fact_id, market_fact_id),
        fact_ledger_payload=freeze(fact_ledger),
    )
    assumption_result = FinalAssumptionLedgerCompilationResult(
        assumption_entries_sha256=canonical_sha256([]),
        prior_fact_ledger_fingerprint=fact_result.base_ledger_sha256,
        final_fact_ledger_fingerprint=final_fact_sha256,
        assumption_ledger_payload=freeze(assumption_ledger),
    )
    request = {
        "schema_version": "2.0.0",
        "fact_ledger": fact_ledger,
        "assumption_ledger": assumption_ledger,
        "company": {"source_fact_ids": []},
        "routing_assessments": {},
        "method_views": {},
        "mckinsey": {"equity_bridge": {"share_denominator_fact_id": current_share_id}},
        "penman": {"market_equity_value_fact_id": market_fact_id},
    }
    return FinalValuationRequestCompilationResult(
        status="compiled",
        issuer_id=preparation.issuer_id,
        valuation_date=preparation.data_cutoff_date,
        price_blind_input_fingerprint=preparation.price_blind_input_fingerprint,
        prepared_market_reference_fingerprint=prepared.fingerprint,
        company_name_fact_id="fact:fixture:company-name",
        company_name_source_document_id="source:fixture:company-name",
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
    return OwnerValuationExecutionClock(
        (allowed + timedelta(microseconds=1)).isoformat(),
        (allowed + timedelta(microseconds=2)).isoformat(),
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
    with pytest.raises(ValueError, match="receipt or Handoff binding changed"):
        replace(
            result,
            kernel_execution_receipt=replace(
                result.kernel_execution_receipt,
                runner_sha256="f" * 64,
            ),
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
    authorization_time = freeze_result.handoffs[-1].transitioned_at
    result = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze_result,
        kernel_repository=Path("/read-only/kernel"),
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256="d" * 64,
        cas_root=Path("/runtime/cas"),
        clock=OwnerValuationExecutionClock(
            authorization_time,
            (
                datetime.fromisoformat(authorization_time.replace("Z", "+00:00"))
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
