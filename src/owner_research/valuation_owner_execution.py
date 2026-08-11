"""Internal Phase 5 v1 orchestration from a prepared market reference to rc.2 output.

The entrypoint deliberately consumes an existing ``OwnerValuationPreparationResult``.
It performs no new external market acquisition and owns no provider.  ContractGraph
validation may replay the already reviewed local evidence bytes.  A successful call
compiles one request, invokes the isolated pinned-kernel runner once, and returns a
validated graph overlay containing only the adjacent request/result Handoff transitions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import ValuationHandoff
from .fingerprints import canonical_json, canonical_sha256
from .validation import ContractGraph, ContractGraphError
from .valuation_final_request import (
    FinalValuationRequestCompilationResult,
    _governed_company_name,
    _governed_market_authority,
    _market_facts,
    _market_source,
    _validated_prepared_market_context,
    compile_final_valuation_request,
)
from .valuation_kernel_projection import project_current_share_lineage
from .valuation_market_execution_policies import (
    FINAL_REQUEST_POLICY_ID,
    FINAL_REQUEST_POLICY_VERSION,
    KERNEL_EXECUTION_POLICY,
    KERNEL_EXECUTION_POLICY_ID,
    KERNEL_EXECUTION_POLICY_VERSION,
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_CONTAINER_IMAGE_CONFIG_DIGEST,
    PINNED_KERNEL_CONTAINER_IMAGE_MANIFEST_DIGEST,
    PINNED_KERNEL_CONTAINER_IMAGE_REFERENCE,
    PINNED_KERNEL_CONTAINER_PLATFORM,
    PINNED_KERNEL_PACKAGE_VERSION,
    PINNED_KERNEL_PLUGIN_VERSION,
    PINNED_KERNEL_REPOSITORY,
    PINNED_KERNEL_SCHEMA_SHA256,
    PINNED_KERNEL_TAG,
)
from .valuation_market_execution_types import (
    FinalRequestCompilationReceipt,
    KernelExecutionReceipt,
)
from .valuation_owner_preparation import OwnerValuationPreparationResult
from .valuation_pinned_kernel import (
    PinnedKernelExecutionError,
    PinnedKernelExecutionResult,
    execute_pinned_kernel,
)
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult


class OwnerValuationExecutionError(ValueError):
    """The prepared request/result boundary could not be advanced exactly."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _preparation_fingerprint(
    preparation: OwnerValuationPreparationResult,
    *,
    expected_freeze_fingerprint: str,
) -> str:
    prepared = preparation.prepared_market_reference
    authority_binding: dict[str, Any] | None = None
    if prepared is not None:
        snapshot = prepared.snapshot
        authority_binding = {
            "authorization_handoffs": tuple(
                sorted(
                    (item.handoff_id, item.fingerprint)
                    for item in prepared.graph.valuation_handoffs
                    if item.handoff_id == snapshot.authorization_handoff_id
                )
            ),
            "validation_contexts": tuple(
                sorted(
                    (item.context_id, item.fingerprint)
                    for item in prepared.graph.market_reference_validation_contexts
                    if item.market_access_result.fingerprint
                    == snapshot.market_access_result_fingerprint
                )
            ),
        }
    return canonical_sha256(
        {
            "status": preparation.status,
            "issuer_id": preparation.issuer_id,
            "data_cutoff_date": preparation.data_cutoff_date,
            "price_blind_input_fingerprint": (preparation.price_blind_input_fingerprint),
            "expected_freeze_fingerprint": expected_freeze_fingerprint,
            "prepared_market_reference_fingerprint": (
                prepared.fingerprint if prepared is not None else None
            ),
            "prepared_authority_binding": authority_binding,
            "issue_codes": preparation.issue_codes,
        }
    )


def _validate_expected_freeze_identity(
    preparation: OwnerValuationPreparationResult,
    expected_freeze: PriceBlindFreezeCompilationResult,
) -> None:
    """Reject untyped or cross-run freeze objects before any request compilation."""

    if type(expected_freeze) is not PriceBlindFreezeCompilationResult:
        raise OwnerValuationExecutionError(
            "owner execution requires an exact price-blind freeze result"
        )
    artifact = expected_freeze.artifact
    handoffs = expected_freeze.handoffs
    if (
        artifact.payload["issuer_id"] != preparation.issuer_id
        or artifact.payload["data_cutoff_date"] != preparation.data_cutoff_date
        or artifact.fingerprint != preparation.price_blind_input_fingerprint
        or any(
            item.issuer_id != preparation.issuer_id
            or item.data_cutoff_date != preparation.data_cutoff_date
            for item in handoffs
        )
        or handoffs[-1].price_blind_input_fingerprint != artifact.fingerprint
    ):
        raise OwnerValuationExecutionError(
            "price-blind freeze identity does not bind owner preparation"
        )


def _expected_freeze_fingerprint(
    expected_freeze: PriceBlindFreezeCompilationResult,
) -> str:
    return expected_freeze.fingerprint


def _stopped_envelope_fingerprint(
    *,
    status: str,
    issuer_id: str,
    data_cutoff_date: str,
    preparation_fingerprint: str,
    expected_freeze_fingerprint: str,
    final_request: FinalValuationRequestCompilationResult,
    final_request_receipt: FinalRequestCompilationReceipt | None,
    quarantined_result_sha256: str | None,
    issue_codes: tuple[str, ...],
    clock: OwnerValuationExecutionClock,
) -> str:
    receipt_fingerprint = (
        final_request_receipt.fingerprint
        if type(final_request_receipt) is FinalRequestCompilationReceipt
        else None
    )
    return canonical_sha256(
        {
            "status": status,
            "issuer_id": issuer_id,
            "data_cutoff_date": data_cutoff_date,
            "preparation_fingerprint": preparation_fingerprint,
            "expected_freeze_fingerprint": expected_freeze_fingerprint,
            "final_request_fingerprint": final_request.fingerprint,
            "final_request_receipt_fingerprint": receipt_fingerprint,
            "quarantined_result_sha256": quarantined_result_sha256,
            "issue_codes": issue_codes,
            "clock": clock,
        }
    )


def _validate_final_request_identity(
    preparation: OwnerValuationPreparationResult,
    final_request: FinalValuationRequestCompilationResult,
) -> None:
    """Bind every compiler outcome to the preparation that produced it."""

    if type(final_request) is not FinalValuationRequestCompilationResult:
        raise OwnerValuationExecutionError(
            "owner execution requires an exact final-request result"
        )
    prepared = preparation.prepared_market_reference
    expected_prepared_fingerprint = (
        prepared.fingerprint
        if final_request.status == "compiled" and prepared is not None
        else None
    )
    if (
        final_request.issuer_id != preparation.issuer_id
        or final_request.valuation_date != preparation.data_cutoff_date
        or final_request.price_blind_input_fingerprint
        != preparation.price_blind_input_fingerprint
        or final_request.prepared_market_reference_fingerprint
        != expected_prepared_fingerprint
        or (final_request.status == "compiled" and prepared is None)
    ):
        raise OwnerValuationExecutionError(
            "final-request result does not bind owner preparation"
        )


def _checked_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise OwnerValuationExecutionError(f"{label} is not a lowercase SHA-256")


def _checked_sha256_digest(value: str, label: str) -> None:
    if not value.startswith("sha256:"):
        raise OwnerValuationExecutionError(f"{label} is not a SHA-256 digest")
    _checked_sha256(value.removeprefix("sha256:"), label)


def _expected_receipt_id(prefix: str, receipt: Any) -> str:
    payload = receipt.to_dict()
    payload.pop("receipt_id")
    return f"{prefix}:{canonical_sha256(payload)[:24]}"


def _utc(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class OwnerValuationExecutionClock:
    """Two injected transition timestamps; the orchestration never reads wall time."""

    request_compiled_at: str
    kernel_result_frozen_at: str

    def __post_init__(self) -> None:
        request_time = _utc(self.request_compiled_at, "request_compiled_at")
        result_time = _utc(self.kernel_result_frozen_at, "kernel_result_frozen_at")
        if request_time >= result_time:
            raise ValueError("owner-execution transition timestamps are not chronological")
        object.__setattr__(self, "request_compiled_at", _timestamp(request_time))
        object.__setattr__(self, "kernel_result_frozen_at", _timestamp(result_time))


def _active_market_authorization(
    preparation: OwnerValuationPreparationResult,
) -> ValuationHandoff:
    """Return the sole active v4 run bound to the prepared security Snapshot."""

    prepared = preparation.prepared_market_reference
    if preparation.status != "prepared" or prepared is None:
        raise OwnerValuationExecutionError("owner execution lacks a prepared market reference")
    graph = prepared.graph
    graph.validate()
    authorization_matches = tuple(
        item
        for item in graph.valuation_handoffs
        if item.handoff_id == prepared.snapshot.authorization_handoff_id
    )
    if len(authorization_matches) != 1:
        raise OwnerValuationExecutionError("prepared Snapshot lacks one graph-owned authorization")
    authorization = authorization_matches[0]
    handoff_index = {item.handoff_id: item for item in graph.valuation_handoffs}
    relevant = tuple(
        item
        for item in graph.valuation_handoffs
        if item.issuer_id == preparation.issuer_id
        and item.data_cutoff_date == preparation.data_cutoff_date
    )
    roots = tuple(item for item in relevant if item.predecessor_handoff_id is None)
    superseded_runs = {
        handoff_index[root.supersedes_handoff_id].handoff_run_id
        for root in roots
        if root.supersedes_handoff_id in handoff_index
    }
    active_runs = {root.handoff_run_id for root in roots} - superseded_runs
    run_handoffs = tuple(
        sorted(
            (
                item
                for item in relevant
                if item.handoff_run_id == authorization.handoff_run_id
            ),
            key=lambda item: item.handoff_version,
        )
    )
    run_handoff_ids = {item.handoff_id for item in run_handoffs}
    if (
        active_runs != {authorization.handoff_run_id}
        or tuple(item.state for item in run_handoffs)
        != (
            "evidence_open",
            "price_blind_candidates_reviewed",
            "price_blind_input_frozen",
            "market_reference_allowed",
        )
        or run_handoffs[-1:] != (authorization,)
        or authorization.handoff_version != 4
        or authorization.fingerprint != prepared.snapshot.authorization_handoff_fingerprint
        or any(
            item.supersedes_handoff_id in run_handoff_ids
            for item in graph.valuation_handoffs
        )
        or any(
            prepared.snapshot.snapshot_id in item.quarantined_market_reference_snapshot_ids
            for item in graph.valuation_handoffs
        )
    ):
        raise OwnerValuationExecutionError(
            "prepared issuer/cutoff/security does not have one active authorization run"
        )
    return authorization


def _replay_request_provenance(
    *,
    preparation: OwnerValuationPreparationResult,
    request: FinalValuationRequestCompilationResult,
) -> None:
    """Re-derive every mutable request provenance field from frozen graph objects."""

    prepared = preparation.prepared_market_reference
    fact_result = request.fact_ledger_result
    if prepared is None or fact_result is None:
        raise OwnerValuationExecutionError("compiled request lacks prepared provenance")
    context = _validated_prepared_market_context(prepared)
    authority = _governed_market_authority(prepared, context)
    projected_market_source = _market_source(prepared, authority)
    current_share_projection = project_current_share_lineage(prepared)
    _, _, quote_witness, market_witness = _market_facts(
        prepared,
        current_share_projection,
        prepared.snapshot.quote_currency,
    )
    legal_name, company_fact, company_source = _governed_company_name(prepared)
    if (
        request.issuer_id != preparation.issuer_id
        or request.valuation_date != preparation.data_cutoff_date
        or request.price_blind_input_fingerprint
        != preparation.price_blind_input_fingerprint
        or request.prepared_market_reference_fingerprint != prepared.fingerprint
        or request.company_legal_name_value != legal_name
        or request.company_name_fact_id != company_fact.fact_id
        or request.company_name_fact_fingerprint != company_fact.fingerprint
        or request.company_name_source_document_id != company_source.document_id
        or request.company_name_source_document_fingerprint != company_source.fingerprint
        or fact_result.current_share_projection != current_share_projection
        or fact_result.quote_projection_witness != quote_witness
        or fact_result.market_equity_projection_witness != market_witness
        or fact_result.market_provider_id != authority["provider_id"]
        or fact_result.market_provider_registration_sha256
        != authority["provider_registration_sha256"]
        or fact_result.market_provider_receipt_id != authority["receipt_id"]
        or fact_result.market_provider_receipt_fingerprint
        != authority["receipt_fingerprint"]
        or fact_result.market_validation_context_id != authority["context_id"]
        or fact_result.market_validation_context_fingerprint
        != authority["context_fingerprint"]
        or fact_result.market_access_result_fingerprint != authority["access_fingerprint"]
        or fact_result.current_share_compilation_fingerprint
        != prepared.current_shares.fingerprint
        or fact_result.market_source_document_id != prepared.market_source.document_id
        or fact_result.market_source_document_fingerprint != prepared.market_source.fingerprint
        or fact_result.market_source_ref_fingerprint
        != canonical_sha256(projected_market_source)
        or fact_result.market_raw_response_sha256 != authority["raw_response_sha256"]
        or fact_result.market_quote_fact_id != prepared.quote_fact.fact_id
        or fact_result.market_quote_fact_fingerprint != prepared.quote_fact.fingerprint
        or fact_result.market_equity_calculation_id
        != prepared.market_equity_calculation.calculation_id
        or fact_result.market_equity_calculation_fingerprint
        != prepared.market_equity_calculation.fingerprint
    ):
        raise OwnerValuationExecutionError(
            "completed request provenance does not replay its frozen preparation"
        )


def _replay_expected_freeze(
    *,
    preparation: OwnerValuationPreparationResult,
    expected_freeze: PriceBlindFreezeCompilationResult,
    authorization: ValuationHandoff,
    request: FinalValuationRequestCompilationResult,
    request_handoff: ValuationHandoff | None = None,
) -> None:
    """Re-attest the compiled ledgers to the exact reviewed price-blind freeze."""

    prepared = preparation.prepared_market_reference
    fact_result = request.fact_ledger_result
    assumption_result = request.assumption_ledger_result
    if (
        prepared is None
        or type(expected_freeze) is not PriceBlindFreezeCompilationResult
        or fact_result is None
        or assumption_result is None
    ):
        raise OwnerValuationExecutionError(
            "compiled request lacks frozen price-blind ledger evidence"
        )
    artifact = expected_freeze.artifact.to_dict()
    reviewed = artifact["reviewed_assumptions"]
    base_ledger = reviewed["augmented_fact_ledger_payload"]
    base_ledger_sha256 = canonical_sha256(base_ledger)
    expected_base_sources = tuple(
        sorted(
            (str(item["source_id"]), canonical_sha256(item))
            for item in base_ledger["sources"]
        )
    )
    expected_base_facts = tuple(
        sorted(
            (str(item["fact_id"]), canonical_sha256(item))
            for item in base_ledger["facts"]
        )
    )
    run_handoffs = tuple(
        sorted(
            (
                item
                for item in prepared.graph.valuation_handoffs
                if item.handoff_run_id == authorization.handoff_run_id
            ),
            key=lambda item: item.handoff_version,
        )
    )
    expected_assumptions = reviewed["assumption_ledger_payload"]["assumptions"]
    actual_assumptions = assumption_result.assumption_ledger_payload["assumptions"]
    if (
        expected_freeze.handoffs[-1:] != (authorization,)
        or run_handoffs != expected_freeze.handoffs
        or expected_freeze.artifact.fingerprint
        != preparation.price_blind_input_fingerprint
        or request.price_blind_input_fingerprint != expected_freeze.artifact.fingerprint
        or authorization.price_blind_input_fingerprint
        != expected_freeze.artifact.fingerprint
        or authorization.protected_mckinsey_sha256
        != artifact["protected_mckinsey_sha256"]
        or authorization.protected_penman_assumptions_sha256
        != artifact["protected_penman_assumptions_sha256"]
        or fact_result.base_ledger_sha256 != base_ledger_sha256
        or canonical_json(fact_result.base_ledger_payload) != canonical_json(base_ledger)
        or fact_result.base_source_fingerprints != expected_base_sources
        or fact_result.base_fact_fingerprints != expected_base_facts
        or assumption_result.prior_fact_ledger_fingerprint != base_ledger_sha256
        or assumption_result.assumption_entries_sha256
        != reviewed["assumption_entries_sha256"]
        or canonical_json(actual_assumptions) != canonical_json(expected_assumptions)
        or canonical_sha256(actual_assumptions)
        != reviewed["assumption_entries_sha256"]
        or (
            request_handoff is not None
            and (
                request_handoff.price_blind_input_fingerprint
                != expected_freeze.artifact.fingerprint
                or request_handoff.protected_mckinsey_sha256
                != artifact["protected_mckinsey_sha256"]
                or request_handoff.protected_penman_assumptions_sha256
                != artifact["protected_penman_assumptions_sha256"]
            )
        )
    ):
        raise OwnerValuationExecutionError(
            "compiled request changed its frozen price-blind ledger"
        )


def _expected_execution_handoffs(
    *,
    authorization: ValuationHandoff,
    snapshot_id: str,
    quote_retrieved_at: str,
    request_sha256: str,
    result_sha256: str,
    clock: OwnerValuationExecutionClock,
) -> tuple[ValuationHandoff, ValuationHandoff]:
    """Rebuild the exact adjacent v5/v6 transition from graph-owned v4."""

    _checked_sha256(request_sha256, "valuation request SHA")
    _checked_sha256(result_sha256, "valuation result SHA")
    request_time = _utc(clock.request_compiled_at, "request_compiled_at")
    result_time = _utc(clock.kernel_result_frozen_at, "kernel_result_frozen_at")
    if (
        request_time
        <= _utc(authorization.transitioned_at, "authorization transitioned_at")
        or request_time <= _utc(quote_retrieved_at, "snapshot quote_retrieved_at")
        or result_time <= request_time
    ):
        raise OwnerValuationExecutionError(
            "execution Handoff timestamps do not follow accepted market evidence"
        )
    prefix = _handoff_prefix(authorization)
    request = replace(
        authorization,
        handoff_id=f"{prefix}:v5",
        handoff_version=5,
        transitioned_at=clock.request_compiled_at,
        state="request_compiled",
        predecessor_handoff_id=authorization.handoff_id,
        market_reference_snapshot_id=snapshot_id,
        valuation_request_sha256=request_sha256,
        valuation_result_sha256=None,
        missing_evidence=(),
    )
    result = replace(
        request,
        handoff_id=f"{prefix}:v6",
        handoff_version=6,
        transitioned_at=clock.kernel_result_frozen_at,
        state="kernel_result_frozen",
        predecessor_handoff_id=request.handoff_id,
        valuation_result_sha256=result_sha256,
        missing_evidence=(),
    )
    return request, result


@dataclass(frozen=True, slots=True)
class OwnerValuationExecutionResult:
    """Closed in-memory result for one prepared request and one pinned-kernel call."""

    status: str
    issuer_id: str
    data_cutoff_date: str
    preparation_fingerprint: str
    preparation: OwnerValuationPreparationResult
    clock: OwnerValuationExecutionClock
    expected_freeze: PriceBlindFreezeCompilationResult | None
    expected_freeze_fingerprint: str
    final_request_result: FinalValuationRequestCompilationResult
    final_request_receipt: FinalRequestCompilationReceipt | None
    kernel_execution_result: PinnedKernelExecutionResult | None
    kernel_execution_receipt: KernelExecutionReceipt | None
    execution_handoffs: tuple[ValuationHandoff, ...]
    validated_graph: ContractGraph | None
    result_bytes: bytes | None
    quarantined_result_sha256: str | None
    stopped_envelope_fingerprint: str | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"completed", "blocked", "specialist_required"}:
            raise ValueError("owner-execution status is not registered")
        raw_issues = tuple(self.issue_codes)
        if any(type(item) is not str or not item for item in raw_issues):
            raise ValueError("owner execution issue codes must be nonempty exact strings")
        issues = tuple(sorted(set(raw_issues)))
        handoffs = tuple(self.execution_handoffs)
        object.__setattr__(self, "execution_handoffs", handoffs)
        object.__setattr__(self, "issue_codes", issues)
        _checked_sha256(self.preparation_fingerprint, "preparation fingerprint")
        _checked_sha256(self.expected_freeze_fingerprint, "expected freeze fingerprint")
        if (
            type(self.preparation) is not OwnerValuationPreparationResult
            or type(self.clock) is not OwnerValuationExecutionClock
            or self.preparation.issuer_id != self.issuer_id
            or self.preparation.data_cutoff_date != self.data_cutoff_date
            or self.preparation_fingerprint
            != _preparation_fingerprint(
                self.preparation,
                expected_freeze_fingerprint=self.expected_freeze_fingerprint,
            )
        ):
            raise ValueError(
                "owner execution changed its frozen preparation fingerprint or clock"
            )
        _validate_final_request_identity(self.preparation, self.final_request_result)
        request = self.final_request_result
        expected_freeze = self.expected_freeze
        requires_freeze = self.status == "completed" or request.status == "compiled"
        if requires_freeze:
            if type(expected_freeze) is not PriceBlindFreezeCompilationResult:
                raise ValueError("compiled owner execution lacks its exact expected freeze")
            _validate_expected_freeze_identity(self.preparation, expected_freeze)
            if self.expected_freeze_fingerprint != _expected_freeze_fingerprint(
                expected_freeze
            ):
                raise ValueError("owner execution changed its expected freeze fingerprint")
        elif expected_freeze is not None:
            raise ValueError("noncompiled owner execution retained a full expected freeze")
        if self.status == "completed":
            if self.stopped_envelope_fingerprint is not None:
                raise ValueError("completed owner execution retained a stopped envelope")
        else:
            if self.stopped_envelope_fingerprint is None:
                raise ValueError("stopped owner execution lacks its envelope fingerprint")
            _checked_sha256(
                self.stopped_envelope_fingerprint,
                "stopped envelope fingerprint",
            )
            if self.stopped_envelope_fingerprint != _stopped_envelope_fingerprint(
                status=self.status,
                issuer_id=self.issuer_id,
                data_cutoff_date=self.data_cutoff_date,
                preparation_fingerprint=self.preparation_fingerprint,
                expected_freeze_fingerprint=self.expected_freeze_fingerprint,
                final_request=request,
                final_request_receipt=self.final_request_receipt,
                quarantined_result_sha256=self.quarantined_result_sha256,
                issue_codes=issues,
                clock=self.clock,
            ):
                raise ValueError("stopped owner execution envelope fingerprint changed")
        if self.quarantined_result_sha256 is not None:
            _checked_sha256(self.quarantined_result_sha256, "quarantined result SHA")

        if self.status != "completed":
            if (
                self.kernel_execution_result is not None
                or self.kernel_execution_receipt is not None
                or handoffs
                or self.validated_graph is not None
                or self.result_bytes is not None
                or not issues
            ):
                raise ValueError("non-completed owner execution promoted a frozen result")
            if self.status == "specialist_required":
                if (
                    request.status != "specialist_required"
                    or self.preparation.status != "specialist_required"
                    or self.final_request_receipt is not None
                    or self.kernel_execution_result is not None
                    or self.quarantined_result_sha256 is not None
                    or issues != request.issue_codes
                ):
                    raise ValueError("specialist route promoted request or execution evidence")
            elif request.status not in {"blocked", "compiled"}:
                raise ValueError("blocked owner execution changed its final-request status")
            elif request.status == "blocked":
                if (
                    self.preparation.status != "blocked"
                    or self.status != "blocked"
                    or self.final_request_receipt is not None
                    or self.quarantined_result_sha256 is not None
                    or issues != request.issue_codes
                ):
                    raise ValueError("blocked compiler result promoted request evidence")
            else:
                prepared = self.preparation.prepared_market_reference
                if prepared is None:
                    raise ValueError("compiled stopped result lacks prepared market evidence")
                request_payload = request.request_payload
                canonical_request = request.canonical_request_json
                request_sha256 = request.request_sha256
                if (
                    request_payload is None
                    or canonical_request is None
                    or request_sha256 is None
                    or canonical_request != canonical_json(request_payload)
                    or request_sha256 != _sha256_bytes(canonical_request.encode("utf-8"))
                ):
                    raise ValueError("compiled stopped request bytes changed")
                _replay_request_provenance(preparation=self.preparation, request=request)
                _replay_expected_freeze(
                    preparation=self.preparation,
                    expected_freeze=expected_freeze,
                    authorization=expected_freeze.handoffs[-1],
                    request=request,
                )
                if type(self.final_request_receipt) is not FinalRequestCompilationReceipt:
                    raise ValueError("compiled stopped result lacks its exact request receipt")
                if len(issues) != 1 or not isinstance(issues[0], str):
                    raise ValueError("compiled stopped result lacks one causal issue code")
                issue_code = issues[0]
                if issue_code == "kernel_execution_blocked:PinnedKernelExecutionError":
                    if self.quarantined_result_sha256 is not None:
                        raise ValueError("kernel execution failure retained quarantine evidence")
                elif issue_code in {
                    "kernel_result_blocked:AttributeError",
                    "kernel_result_blocked:ContractGraphError",
                    "kernel_result_blocked:KeyError",
                    "kernel_result_blocked:OwnerValuationExecutionError",
                    "kernel_result_blocked:TypeError",
                    "kernel_result_blocked:ValueError",
                }:
                    if self.quarantined_result_sha256 is None:
                        raise ValueError("kernel result failure lacks quarantine evidence")
                else:
                    raise ValueError("compiled stopped result has an invalid causal issue")
                context = _compiled_context(
                    preparation=self.preparation,
                    expected_freeze=expected_freeze,
                    final_request=request,
                    clock=self.clock,
                )
                if self.final_request_receipt != _final_request_receipt(context):
                    raise ValueError("stopped request receipt binding changed")
            return

        request = self.final_request_result
        preparation = self.preparation
        prepared = preparation.prepared_market_reference
        execution = self.kernel_execution_result
        request_receipt = self.final_request_receipt
        execution_receipt = self.kernel_execution_receipt
        graph = self.validated_graph
        if (
            request.status != "compiled"
            or preparation.status != "prepared"
            or prepared is None
            or type(expected_freeze) is not PriceBlindFreezeCompilationResult
            or request.issuer_id != self.issuer_id
            or request.valuation_date != self.data_cutoff_date
            or request.request_sha256 is None
            or request.request_payload is None
            or execution is None
            or request_receipt is None
            or execution_receipt is None
            or graph is None
            or self.result_bytes is None
            or self.quarantined_result_sha256 is not None
            or issues
            or tuple(item.state for item in handoffs)
            != ("request_compiled", "kernel_result_frozen")
        ):
            raise ValueError("completed owner execution is incomplete")
        request_handoff, result_handoff = handoffs
        authorization = _active_market_authorization(preparation)
        _replay_request_provenance(preparation=preparation, request=request)
        result_sha256 = _sha256_bytes(self.result_bytes)
        fact_result = request.fact_ledger_result
        assumption_result = request.assumption_ledger_result
        if fact_result is None or assumption_result is None:
            raise ValueError("completed owner execution lacks compiled ledger evidence")
        _replay_expected_freeze(
            preparation=preparation,
            expected_freeze=expected_freeze,
            authorization=authorization,
            request=request,
            request_handoff=request_handoff,
        )
        if (
            execution.result_bytes != self.result_bytes
            or execution.request_sha256 != request.request_sha256
            or execution.result_sha256 != result_sha256
            or request.price_blind_input_fingerprint
            != request_handoff.price_blind_input_fingerprint
            or request_receipt.issuer_id != request.issuer_id
            or request_receipt.handoff_run_id != request_handoff.handoff_run_id
            or request_receipt.valuation_request_sha256 != request.request_sha256
            or request_receipt.receipt_id
            != _expected_receipt_id(
                f"final-request-receipt:{request.issuer_id}",
                request_receipt,
            )
            or request_receipt.company_legal_name_value
            != request.company_legal_name_value
            or request_receipt.company_name_fact_id != request.company_name_fact_id
            or request_receipt.company_name_fact_fingerprint
            != request.company_name_fact_fingerprint
            or request_receipt.company_name_source_document_id
            != request.company_name_source_document_id
            or request_receipt.company_name_source_document_fingerprint
            != request.company_name_source_document_fingerprint
            or request_receipt.company_identity_binding_sha256
            != request.company_identity_binding_sha256
            or request_receipt.market_provider_id != fact_result.market_provider_id
            or request_receipt.market_provider_receipt_id != fact_result.market_provider_receipt_id
            or request_receipt.market_provider_receipt_fingerprint
            != fact_result.market_provider_receipt_fingerprint
            or request_receipt.market_provider_registration_sha256
            != fact_result.market_provider_registration_sha256
            or request_receipt.market_validation_context_id
            != fact_result.market_validation_context_id
            or request_receipt.market_validation_context_fingerprint
            != fact_result.market_validation_context_fingerprint
            or request_receipt.market_access_result_fingerprint
            != fact_result.market_access_result_fingerprint
            or request_receipt.current_share_compilation_fingerprint
            != fact_result.current_share_compilation_fingerprint
            or request_receipt.market_source_document_id
            != fact_result.market_source_document_id
            or request_receipt.market_source_document_fingerprint
            != fact_result.market_source_document_fingerprint
            or request_receipt.market_source_ref_fingerprint
            != fact_result.market_source_ref_fingerprint
            or request_receipt.market_raw_response_sha256
            != fact_result.market_raw_response_sha256
            or request_receipt.market_quote_fact_id != fact_result.market_quote_fact_id
            or request_receipt.market_quote_fact_fingerprint
            != fact_result.market_quote_fact_fingerprint
            or request_receipt.market_equity_calculation_id
            != fact_result.market_equity_calculation_id
            or request_receipt.market_equity_calculation_fingerprint
            != fact_result.market_equity_calculation_fingerprint
            or request_receipt.market_evidence_binding_sha256
            != fact_result.market_evidence_binding_sha256
            or request_receipt.current_share_projection_sha256
            != fact_result.current_share_projection.fingerprint
            or request_receipt.numeric_projection_sha256
            != _numeric_projection_sha256(request)
            or request_receipt.added_source_ids != fact_result.added_source_ids
            or request_receipt.added_fact_ids != fact_result.added_fact_ids
            or request_receipt.price_blind_fact_ledger_sha256
            != fact_result.base_ledger_sha256
            or request_receipt.final_fact_ledger_sha256
            != canonical_sha256(fact_result.fact_ledger_payload)
            or request_receipt.assumption_entries_before_sha256
            != assumption_result.assumption_entries_sha256
            or request_receipt.assumption_entries_after_sha256
            != assumption_result.assumption_entries_sha256
            or request_receipt.price_blind_input_before_sha256
            != request_handoff.price_blind_input_fingerprint
            or request_receipt.price_blind_input_after_sha256
            != request_handoff.price_blind_input_fingerprint
            or request_receipt.protected_mckinsey_before_sha256
            != request_handoff.protected_mckinsey_sha256
            or request_receipt.protected_mckinsey_after_sha256
            != request_handoff.protected_mckinsey_sha256
            or request_receipt.protected_penman_before_sha256
            != request_handoff.protected_penman_assumptions_sha256
            or request_receipt.protected_penman_after_sha256
            != request_handoff.protected_penman_assumptions_sha256
            or execution_receipt.request_sha256 != request.request_sha256
            or execution_receipt.result_sha256 != result_sha256
            or execution_receipt.receipt_id
            != _expected_receipt_id("kernel-execution-receipt", execution_receipt)
            or execution_receipt.wheel_sha256 != execution.kernel_wheel_sha256
            or execution_receipt.runtime_authority_sha256 != execution.runtime_authority_sha256
            or execution_receipt.runtime_manifest_file_sha256
            != execution.runtime_manifest_file_sha256
            or execution_receipt.runtime_manifest_fingerprint
            != execution.runtime_manifest_fingerprint
            or execution_receipt.runner_sha256 != execution.runner_sha256
            or execution_receipt.result_schema_sha256 != execution.result_schema_sha256
            or execution_receipt.wheel_inventory_sha256 != execution.wheel_inventory_sha256
            or execution_receipt.docker_executable_sha256 != execution.docker_executable_sha256
            or execution_receipt.container_image_reference != execution.container_image_reference
            or execution_receipt.container_image_manifest_digest
            != execution.container_image_manifest_digest
            or execution_receipt.container_image_config_digest
            != execution.container_image_config_digest
            or execution_receipt.container_platform != execution.container_platform
            or execution_receipt.container_identity_sha256 != execution.container_identity_sha256
            or execution_receipt.docker_image_inspect_sha256
            != execution.docker_image_inspect_sha256
            or execution_receipt.container_security_profile_sha256
            != execution.container_security_profile_sha256
            or execution_receipt.trusted_workflow_attestation_sha256
            != execution.trusted_workflow_attestation_sha256
            or execution_receipt.execution_boundary != execution.execution_boundary
            or execution_receipt.fact_ledger_fingerprint != execution.fact_ledger_fingerprint
            or execution_receipt.assumption_ledger_fingerprint
            != execution.assumption_ledger_fingerprint
            or execution_receipt.model_input_fingerprint != execution.model_input_fingerprint
            or execution_receipt.call_count != execution.kernel_call_count
            or execution.kernel_call_count != 1
            or request_handoff.market_reference_snapshot_id
            != request_receipt.market_reference_snapshot_id
            or request_handoff.valuation_request_sha256 != request.request_sha256
            or request_handoff.valuation_result_sha256 is not None
            or result_handoff.predecessor_handoff_id != request_handoff.handoff_id
            or result_handoff.market_reference_snapshot_id
            != request_handoff.market_reference_snapshot_id
            or result_handoff.valuation_request_sha256 != request_handoff.valuation_request_sha256
            or result_handoff.valuation_result_sha256 != result_sha256
            or request_handoff.missing_evidence
            or result_handoff.missing_evidence
        ):
            raise ValueError("owner-execution receipt or Handoff binding changed")
        expected_handoffs = _expected_execution_handoffs(
            authorization=authorization,
            snapshot_id=prepared.snapshot.snapshot_id,
            quote_retrieved_at=prepared.snapshot.quote_retrieved_at,
            request_sha256=request.request_sha256,
            result_sha256=result_sha256,
            clock=self.clock,
        )
        if handoffs != expected_handoffs:
            raise ValueError("owner-execution deterministic Handoff binding changed")
        expected_graph = replace(
            prepared.graph,
            valuation_handoffs=(*prepared.graph.valuation_handoffs, *expected_handoffs),
        )
        if graph != expected_graph:
            raise ValueError("validated graph is not the exact execution overlay")
        graph.validate()


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    preparation: OwnerValuationPreparationResult
    expected_freeze: PriceBlindFreezeCompilationResult
    final_request: FinalValuationRequestCompilationResult
    graph: ContractGraph
    authorization: ValuationHandoff
    request_bytes: bytes


def _compiled_context(
    *,
    preparation: OwnerValuationPreparationResult,
    expected_freeze: PriceBlindFreezeCompilationResult,
    final_request: FinalValuationRequestCompilationResult,
    clock: OwnerValuationExecutionClock,
) -> _ExecutionContext:
    prepared = preparation.prepared_market_reference
    if preparation.status != "prepared" or prepared is None:
        raise OwnerValuationExecutionError("compiled request lacks a prepared market reference")
    if final_request.status != "compiled":
        raise OwnerValuationExecutionError("owner execution received a non-compiled request")
    request_payload = final_request.request_payload
    canonical_request = final_request.canonical_request_json
    request_sha256 = final_request.request_sha256
    if request_payload is None or canonical_request is None or request_sha256 is None:
        raise OwnerValuationExecutionError("compiled request bytes are incomplete")
    request_bytes = canonical_request.encode("utf-8")
    if canonical_request != canonical_json(request_payload) or request_sha256 != _sha256_bytes(
        request_bytes
    ):
        raise OwnerValuationExecutionError("compiled request bytes or SHA changed")
    if (
        final_request.issuer_id != preparation.issuer_id
        or final_request.valuation_date != preparation.data_cutoff_date
        or final_request.price_blind_input_fingerprint != preparation.price_blind_input_fingerprint
        or final_request.prepared_market_reference_fingerprint != prepared.fingerprint
    ):
        raise OwnerValuationExecutionError("compiled request does not bind its preparation")
    _replay_request_provenance(preparation=preparation, request=final_request)

    graph = prepared.graph
    graph.validate()
    active_authorization = _active_market_authorization(preparation)
    _replay_expected_freeze(
        preparation=preparation,
        expected_freeze=expected_freeze,
        authorization=active_authorization,
        request=final_request,
    )
    try:
        authorization = expected_freeze.handoffs[-1]
    except IndexError as exc:
        raise OwnerValuationExecutionError("price-blind freeze lacks market authorization") from exc
    run_handoffs = tuple(
        sorted(
            (
                item
                for item in graph.valuation_handoffs
                if item.handoff_run_id == authorization.handoff_run_id
            ),
            key=lambda item: item.handoff_version,
        )
    )
    matched_snapshots = tuple(
        item
        for item in graph.market_reference_snapshots
        if item.snapshot_id == prepared.snapshot.snapshot_id
    )
    if (
        authorization.state != "market_reference_allowed"
        or authorization.handoff_version != 4
        or authorization != active_authorization
        or run_handoffs != expected_freeze.handoffs
        or tuple(item.state for item in run_handoffs)
        != (
            "evidence_open",
            "price_blind_candidates_reviewed",
            "price_blind_input_frozen",
            "market_reference_allowed",
        )
        or prepared.snapshot.authorization_handoff_id != authorization.handoff_id
        or prepared.snapshot.authorization_handoff_fingerprint != authorization.fingerprint
        or len(matched_snapshots) != 1
        or matched_snapshots[0] != prepared.snapshot
        or expected_freeze.artifact.fingerprint != preparation.price_blind_input_fingerprint
    ):
        raise OwnerValuationExecutionError(
            "prepared graph does not end at the exact v4 market authorization"
        )
    request_compiled_at = _utc(clock.request_compiled_at, "request_compiled_at")
    if request_compiled_at <= _utc(
        authorization.transitioned_at,
        "authorization transitioned_at",
    ) or request_compiled_at <= _utc(
        prepared.snapshot.quote_retrieved_at,
        "snapshot quote_retrieved_at",
    ):
        raise OwnerValuationExecutionError(
            "request compilation transition does not follow accepted market evidence"
        )
    prefix = _handoff_prefix(authorization)
    existing_ids = {item.handoff_id for item in graph.valuation_handoffs}
    if {f"{prefix}:v5", f"{prefix}:v6"}.intersection(existing_ids):
        raise OwnerValuationExecutionError("deterministic execution Handoff ID collides")
    return _ExecutionContext(
        preparation=preparation,
        expected_freeze=expected_freeze,
        final_request=final_request,
        graph=graph,
        authorization=authorization,
        request_bytes=request_bytes,
    )


def _numeric_projection_sha256(
    result: FinalValuationRequestCompilationResult,
) -> str:
    fact_result = result.fact_ledger_result
    if fact_result is None:
        raise OwnerValuationExecutionError("compiled request lacks its FactLedger result")
    return canonical_sha256(
        {
            "current_share_numeric_witnesses": [
                item.to_dict() for item in fact_result.current_share_projection.numeric_witnesses
            ],
            "quote_projection_witness": fact_result.quote_projection_witness.to_dict(),
            "market_equity_projection_witness": (
                fact_result.market_equity_projection_witness.to_dict()
            ),
        }
    )


def _final_request_receipt(context: _ExecutionContext) -> FinalRequestCompilationReceipt:
    result = context.final_request
    fact_result = result.fact_ledger_result
    assumption_result = result.assumption_ledger_result
    request_sha256 = result.request_sha256
    if (
        fact_result is None
        or assumption_result is None
        or request_sha256 is None
        or result.company_name_fact_id is None
        or result.company_legal_name_value is None
        or result.company_name_fact_fingerprint is None
        or result.company_name_source_document_id is None
        or result.company_name_source_document_fingerprint is None
        or result.company_identity_binding_sha256 is None
    ):
        raise OwnerValuationExecutionError("compiled request lacks receipt evidence")
    artifact = context.expected_freeze.artifact.to_dict()
    final_fact_ledger_sha256 = canonical_sha256(fact_result.fact_ledger_payload)
    if (
        final_fact_ledger_sha256 != assumption_result.final_fact_ledger_fingerprint
        or assumption_result.assumption_entries_sha256
        != canonical_sha256(assumption_result.assumption_ledger_payload["assumptions"])
        or artifact["price_blind_input_fingerprint"]
        != context.preparation.price_blind_input_fingerprint
        or artifact["protected_mckinsey_sha256"] != context.authorization.protected_mckinsey_sha256
        or artifact["protected_penman_assumptions_sha256"]
        != context.authorization.protected_penman_assumptions_sha256
    ):
        raise OwnerValuationExecutionError("final-request receipt evidence does not replay")
    payload: dict[str, Any] = {
        "policy_id": FINAL_REQUEST_POLICY_ID,
        "policy_version": FINAL_REQUEST_POLICY_VERSION,
        "issuer_id": result.issuer_id,
        "handoff_run_id": context.authorization.handoff_run_id,
        "market_reference_snapshot_id": (
            context.preparation.prepared_market_reference.snapshot.snapshot_id
        ),
        "company_legal_name_value": result.company_legal_name_value,
        "company_name_fact_id": result.company_name_fact_id,
        "company_name_fact_fingerprint": result.company_name_fact_fingerprint,
        "company_name_source_document_id": result.company_name_source_document_id,
        "company_name_source_document_fingerprint": (
            result.company_name_source_document_fingerprint
        ),
        "company_identity_binding_sha256": result.company_identity_binding_sha256,
        "market_provider_id": fact_result.market_provider_id,
        "market_provider_receipt_id": fact_result.market_provider_receipt_id,
        "market_provider_receipt_fingerprint": (fact_result.market_provider_receipt_fingerprint),
        "market_provider_registration_sha256": (
            fact_result.market_provider_registration_sha256
        ),
        "market_validation_context_id": fact_result.market_validation_context_id,
        "market_validation_context_fingerprint": (
            fact_result.market_validation_context_fingerprint
        ),
        "market_access_result_fingerprint": (
            fact_result.market_access_result_fingerprint
        ),
        "current_share_compilation_fingerprint": (
            fact_result.current_share_compilation_fingerprint
        ),
        "market_source_document_id": fact_result.market_source_document_id,
        "market_source_document_fingerprint": (
            fact_result.market_source_document_fingerprint
        ),
        "market_source_ref_fingerprint": fact_result.market_source_ref_fingerprint,
        "market_raw_response_sha256": fact_result.market_raw_response_sha256,
        "market_quote_fact_id": fact_result.market_quote_fact_id,
        "market_quote_fact_fingerprint": fact_result.market_quote_fact_fingerprint,
        "market_equity_calculation_id": fact_result.market_equity_calculation_id,
        "market_equity_calculation_fingerprint": (
            fact_result.market_equity_calculation_fingerprint
        ),
        "market_evidence_binding_sha256": fact_result.market_evidence_binding_sha256,
        "current_share_projection_sha256": (fact_result.current_share_projection.fingerprint),
        "numeric_projection_sha256": _numeric_projection_sha256(result),
        "added_source_ids": fact_result.added_source_ids,
        "added_fact_ids": fact_result.added_fact_ids,
        "price_blind_fact_ledger_sha256": fact_result.base_ledger_sha256,
        "final_fact_ledger_sha256": final_fact_ledger_sha256,
        "assumption_entries_before_sha256": assumption_result.assumption_entries_sha256,
        "assumption_entries_after_sha256": assumption_result.assumption_entries_sha256,
        "price_blind_input_before_sha256": artifact["price_blind_input_fingerprint"],
        "price_blind_input_after_sha256": artifact["price_blind_input_fingerprint"],
        "protected_mckinsey_before_sha256": artifact["protected_mckinsey_sha256"],
        "protected_mckinsey_after_sha256": artifact["protected_mckinsey_sha256"],
        "protected_penman_before_sha256": artifact["protected_penman_assumptions_sha256"],
        "protected_penman_after_sha256": artifact["protected_penman_assumptions_sha256"],
        "valuation_request_sha256": request_sha256,
        "status": "validated",
        "reason_codes": (),
    }
    payload["receipt_id"] = (
        f"final-request-receipt:{result.issuer_id}:{canonical_sha256(payload)[:24]}"
    )
    return FinalRequestCompilationReceipt(**payload)


def _kernel_execution_receipt(
    execution: PinnedKernelExecutionResult,
) -> KernelExecutionReceipt:
    """Project the final runner attestation into the existing closed receipt."""

    payload: dict[str, Any] = {
        "policy_id": KERNEL_EXECUTION_POLICY_ID,
        "policy_version": KERNEL_EXECUTION_POLICY_VERSION,
        "repository": PINNED_KERNEL_REPOSITORY,
        "tag": PINNED_KERNEL_TAG,
        "commit": PINNED_KERNEL_COMMIT,
        "package_version": PINNED_KERNEL_PACKAGE_VERSION,
        "plugin_version": PINNED_KERNEL_PLUGIN_VERSION,
        "schema_sha256": PINNED_KERNEL_SCHEMA_SHA256,
        "wheel_sha256": execution.kernel_wheel_sha256,
        "runtime_authority_sha256": execution.runtime_authority_sha256,
        "runtime_manifest_file_sha256": execution.runtime_manifest_file_sha256,
        "runtime_manifest_fingerprint": execution.runtime_manifest_fingerprint,
        "runner_sha256": execution.runner_sha256,
        "result_schema_sha256": execution.result_schema_sha256,
        "wheel_inventory_sha256": execution.wheel_inventory_sha256,
        "docker_executable_sha256": execution.docker_executable_sha256,
        "container_image_reference": execution.container_image_reference,
        "container_image_manifest_digest": execution.container_image_manifest_digest,
        "container_image_config_digest": execution.container_image_config_digest,
        "container_platform": execution.container_platform,
        "container_identity_sha256": execution.container_identity_sha256,
        "docker_image_inspect_sha256": execution.docker_image_inspect_sha256,
        "container_security_profile_sha256": (execution.container_security_profile_sha256),
        "trusted_workflow_attestation_sha256": (execution.trusted_workflow_attestation_sha256),
        "execution_boundary": execution.execution_boundary,
        "execution_mode": KERNEL_EXECUTION_POLICY.execution_mode,
        "request_transport": KERNEL_EXECUTION_POLICY.request_transport,
        "result_transport": KERNEL_EXECUTION_POLICY.result_transport,
        "network_mode": KERNEL_EXECUTION_POLICY.network_mode,
        "request_sha256": execution.request_sha256,
        "result_sha256": execution.result_sha256,
        "fact_ledger_fingerprint": execution.fact_ledger_fingerprint,
        "assumption_ledger_fingerprint": execution.assumption_ledger_fingerprint,
        "model_input_fingerprint": execution.model_input_fingerprint,
        "call_count": execution.kernel_call_count,
        "exit_code": 0,
        "result_preserved": True,
        "status": "succeeded",
        "reason_codes": (),
    }
    payload["receipt_id"] = f"kernel-execution-receipt:{canonical_sha256(payload)[:24]}"
    return KernelExecutionReceipt(**payload)


def _handoff_prefix(authorization: ValuationHandoff) -> str:
    suffix = f":v{authorization.handoff_version}"
    if authorization.handoff_id.endswith(suffix):
        return authorization.handoff_id[: -len(suffix)]
    digest = canonical_sha256(
        {
            "handoff_run_id": authorization.handoff_run_id,
            "issuer_id": authorization.issuer_id,
        }
    )
    return f"valuation-handoff:{authorization.issuer_id}:{digest[:20]}"


def _execution_handoffs(
    *,
    context: _ExecutionContext,
    clock: OwnerValuationExecutionClock,
    result_sha256: str,
) -> tuple[ValuationHandoff, ValuationHandoff]:
    request_sha256 = context.final_request.request_sha256
    prepared = context.preparation.prepared_market_reference
    if request_sha256 is None or prepared is None:
        raise OwnerValuationExecutionError("execution Handoff lacks request evidence")
    request, result = _expected_execution_handoffs(
        authorization=context.authorization,
        snapshot_id=prepared.snapshot.snapshot_id,
        quote_retrieved_at=prepared.snapshot.quote_retrieved_at,
        request_sha256=request_sha256,
        result_sha256=result_sha256,
        clock=clock,
    )
    existing = {item.handoff_id for item in context.graph.valuation_handoffs}
    if request.handoff_id in existing or result.handoff_id in existing:
        raise OwnerValuationExecutionError("deterministic execution Handoff ID collides")
    return request, result


def _validated_overlay(
    context: _ExecutionContext,
    handoffs: tuple[ValuationHandoff, ValuationHandoff],
) -> ContractGraph:
    overlay = replace(
        context.graph,
        valuation_handoffs=(*context.graph.valuation_handoffs, *handoffs),
    )
    try:
        overlay.validate()
    except ContractGraphError as exc:
        raise OwnerValuationExecutionError("execution Handoff graph does not replay") from exc
    return overlay


def _verify_kernel_result(
    *,
    context: _ExecutionContext,
    execution: PinnedKernelExecutionResult,
    expected_runtime_manifest_file_sha256: str,
) -> None:
    result_bytes = execution.result_bytes
    if type(result_bytes) is not bytes or not result_bytes:
        raise OwnerValuationExecutionError("kernel stdout is not preserved bytes")
    try:
        payload = json.loads(result_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OwnerValuationExecutionError("kernel stdout is not valid JSON") from exc
    request = context.final_request.request_payload
    if request is None:
        raise OwnerValuationExecutionError("kernel execution lacks request payload")
    fact_fingerprint = canonical_sha256(request["fact_ledger"])
    assumption_fingerprint = canonical_sha256(request["assumption_ledger"])
    for value, label in (
        (execution.runtime_authority_sha256, "runtime authority SHA"),
        (execution.runtime_manifest_file_sha256, "runtime manifest file SHA"),
        (execution.runtime_manifest_fingerprint, "runtime manifest fingerprint"),
        (execution.runner_sha256, "runner SHA"),
        (execution.result_schema_sha256, "result Schema SHA"),
        (execution.wheel_inventory_sha256, "wheel inventory SHA"),
        (execution.container_security_profile_sha256, "container security profile SHA"),
    ):
        _checked_sha256(value, label)
    _checked_sha256_digest(
        execution.container_image_manifest_digest,
        "container image manifest digest",
    )
    _checked_sha256_digest(
        execution.container_image_config_digest,
        "container image config digest",
    )
    if (
        execution.container_image_reference != PINNED_KERNEL_CONTAINER_IMAGE_REFERENCE
        or execution.container_image_manifest_digest
        != PINNED_KERNEL_CONTAINER_IMAGE_MANIFEST_DIGEST
        or execution.container_image_config_digest != PINNED_KERNEL_CONTAINER_IMAGE_CONFIG_DIGEST
        or execution.container_platform != PINNED_KERNEL_CONTAINER_PLATFORM
    ):
        raise OwnerValuationExecutionError("container image identity does not replay")
    if execution.execution_boundary == "trusted_host_docker_launcher":
        host_evidence = (
            execution.docker_executable_sha256,
            execution.container_identity_sha256,
            execution.docker_image_inspect_sha256,
        )
        if any(value is None for value in host_evidence) or (
            execution.trusted_workflow_attestation_sha256 is not None
        ):
            raise OwnerValuationExecutionError(
                "trusted host execution lacks exclusive Docker evidence"
            )
        for value, label in zip(
            host_evidence,
            ("Docker executable SHA", "container identity SHA", "Docker inspect SHA"),
            strict=True,
        ):
            assert value is not None
            _checked_sha256(value, label)
    elif execution.execution_boundary == "trusted_workflow_authorized_container":
        if (
            execution.docker_executable_sha256 is not None
            or execution.container_identity_sha256 is not None
            or execution.docker_image_inspect_sha256 is not None
            or execution.trusted_workflow_attestation_sha256 is None
        ):
            raise OwnerValuationExecutionError(
                "trusted workflow execution lacks exclusive workflow evidence"
            )
        _checked_sha256(
            execution.trusted_workflow_attestation_sha256,
            "trusted workflow attestation SHA",
        )
    else:
        raise OwnerValuationExecutionError("kernel execution boundary is not registered")
    if (
        not isinstance(payload, dict)
        or canonical_json(payload).encode("utf-8") != result_bytes
        or execution.request_sha256 != _sha256_bytes(context.request_bytes)
        or execution.result_sha256 != _sha256_bytes(result_bytes)
        or execution.runtime_manifest_file_sha256 != expected_runtime_manifest_file_sha256
        or execution.kernel_call_count != 1
        or execution.kernel_wheel_sha256 != KERNEL_EXECUTION_POLICY.exact_wheel_sha256
        or execution.fact_ledger_fingerprint != fact_fingerprint
        or execution.assumption_ledger_fingerprint != assumption_fingerprint
        or execution.model_input_fingerprint != context.final_request.request_sha256
        or payload.get("fact_ledger_fingerprint") != fact_fingerprint
        or payload.get("assumption_ledger_fingerprint") != assumption_fingerprint
        or payload.get("model_input_fingerprint") != context.final_request.request_sha256
    ):
        raise OwnerValuationExecutionError(
            "kernel result bytes or input fingerprints do not replay"
        )


def _blocked_final_request(
    preparation: OwnerValuationPreparationResult,
    issue_code: str,
) -> FinalValuationRequestCompilationResult:
    """Return a closed blocked result without retaining rejected compiled bytes."""

    return FinalValuationRequestCompilationResult(
        status="blocked",
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
        issue_codes=(issue_code,),
    )


def _noncompiled_preparation(
    preparation: OwnerValuationPreparationResult,
    *,
    status: str,
    issue_codes: tuple[str, ...],
) -> OwnerValuationPreparationResult:
    if preparation.status == status and preparation.issue_codes == issue_codes:
        return preparation
    return OwnerValuationPreparationResult(
        status=status,
        issuer_id=preparation.issuer_id,
        data_cutoff_date=preparation.data_cutoff_date,
        price_blind_input_fingerprint=preparation.price_blind_input_fingerprint,
        prepared_market_reference=None,
        issue_codes=issue_codes,
    )


def _stopped(
    *,
    preparation: OwnerValuationPreparationResult,
    clock: OwnerValuationExecutionClock,
    expected_freeze: PriceBlindFreezeCompilationResult,
    final_request: FinalValuationRequestCompilationResult,
    status: str,
    issue_codes: tuple[str, ...],
    final_request_receipt: FinalRequestCompilationReceipt | None = None,
    quarantined_result_sha256: str | None = None,
) -> OwnerValuationExecutionResult:
    retained_freeze = expected_freeze if final_request.status == "compiled" else None
    freeze_fingerprint = _expected_freeze_fingerprint(expected_freeze)
    preparation_fingerprint = _preparation_fingerprint(
        preparation,
        expected_freeze_fingerprint=freeze_fingerprint,
    )
    envelope_fingerprint = _stopped_envelope_fingerprint(
        status=status,
        issuer_id=preparation.issuer_id,
        data_cutoff_date=preparation.data_cutoff_date,
        preparation_fingerprint=preparation_fingerprint,
        expected_freeze_fingerprint=freeze_fingerprint,
        final_request=final_request,
        final_request_receipt=final_request_receipt,
        quarantined_result_sha256=quarantined_result_sha256,
        issue_codes=issue_codes,
        clock=clock,
    )
    return OwnerValuationExecutionResult(
        status=status,
        issuer_id=preparation.issuer_id,
        data_cutoff_date=preparation.data_cutoff_date,
        preparation_fingerprint=preparation_fingerprint,
        preparation=preparation,
        clock=clock,
        expected_freeze=retained_freeze,
        expected_freeze_fingerprint=freeze_fingerprint,
        final_request_result=final_request,
        final_request_receipt=final_request_receipt,
        kernel_execution_result=None,
        kernel_execution_receipt=None,
        execution_handoffs=(),
        validated_graph=None,
        result_bytes=None,
        quarantined_result_sha256=quarantined_result_sha256,
        stopped_envelope_fingerprint=envelope_fingerprint,
        issue_codes=issue_codes,
    )


def execute_owner_valuation(
    *,
    preparation: OwnerValuationPreparationResult,
    expected_freeze: PriceBlindFreezeCompilationResult,
    kernel_repository: Path,
    runtime_manifest: Path,
    runtime_manifest_file_sha256: str,
    cas_root: Path,
    clock: OwnerValuationExecutionClock,
    timeout_seconds: int = 90,
) -> OwnerValuationExecutionResult:
    """Compile once and execute once without reopening the market boundary."""

    _validate_expected_freeze_identity(preparation, expected_freeze)
    final_request = compile_final_valuation_request(
        preparation=preparation,
        expected_freeze=expected_freeze,
        kernel_repository=kernel_repository,
    )
    _validate_final_request_identity(preparation, final_request)
    if final_request.status != "compiled":
        stopped_preparation = _noncompiled_preparation(
            preparation,
            status=final_request.status,
            issue_codes=final_request.issue_codes,
        )
        return _stopped(
            preparation=stopped_preparation,
            clock=clock,
            expected_freeze=expected_freeze,
            final_request=final_request,
            status=(
                "specialist_required"
                if final_request.status == "specialist_required"
                else "blocked"
            ),
            issue_codes=final_request.issue_codes,
        )

    try:
        context = _compiled_context(
            preparation=preparation,
            expected_freeze=expected_freeze,
            final_request=final_request,
            clock=clock,
        )
        _checked_sha256(
            runtime_manifest_file_sha256,
            "expected runtime manifest file SHA",
        )
        request_receipt = _final_request_receipt(context)
    except (
        AttributeError,
        ContractGraphError,
        KeyError,
        OwnerValuationExecutionError,
        TypeError,
        ValueError,
    ) as exc:
        issue_code = f"owner_execution_preflight_blocked:{type(exc).__name__}"
        stopped_preparation = _noncompiled_preparation(
            preparation,
            status="blocked",
            issue_codes=(issue_code,),
        )
        return _stopped(
            preparation=stopped_preparation,
            clock=clock,
            expected_freeze=expected_freeze,
            final_request=_blocked_final_request(stopped_preparation, issue_code),
            status="blocked",
            issue_codes=(issue_code,),
        )

    try:
        execution = execute_pinned_kernel(
            context.request_bytes,
            runtime_manifest=runtime_manifest,
            runtime_manifest_file_sha256=runtime_manifest_file_sha256,
            cas_root=cas_root,
            timeout_seconds=timeout_seconds,
        )
    except PinnedKernelExecutionError as exc:
        return _stopped(
            preparation=preparation,
            clock=clock,
            expected_freeze=expected_freeze,
            final_request=final_request,
            final_request_receipt=request_receipt,
            status="blocked",
            issue_codes=(f"kernel_execution_blocked:{type(exc).__name__}",),
        )

    try:
        _verify_kernel_result(
            context=context,
            execution=execution,
            expected_runtime_manifest_file_sha256=runtime_manifest_file_sha256,
        )
        execution_receipt = _kernel_execution_receipt(execution)
        handoffs = _execution_handoffs(
            context=context,
            clock=clock,
            result_sha256=execution.result_sha256,
        )
        graph = _validated_overlay(context, handoffs)
    except (
        AttributeError,
        ContractGraphError,
        KeyError,
        OwnerValuationExecutionError,
        TypeError,
        ValueError,
    ) as exc:
        quarantined_sha = (
            _sha256_bytes(execution.result_bytes) if type(execution.result_bytes) is bytes else None
        )
        return _stopped(
            preparation=preparation,
            clock=clock,
            expected_freeze=expected_freeze,
            final_request=final_request,
            final_request_receipt=request_receipt,
            status="blocked",
            quarantined_result_sha256=quarantined_sha,
            issue_codes=(f"kernel_result_blocked:{type(exc).__name__}",),
        )

    freeze_fingerprint = _expected_freeze_fingerprint(expected_freeze)
    return OwnerValuationExecutionResult(
        status="completed",
        issuer_id=preparation.issuer_id,
        data_cutoff_date=preparation.data_cutoff_date,
        preparation_fingerprint=_preparation_fingerprint(
            preparation,
            expected_freeze_fingerprint=freeze_fingerprint,
        ),
        preparation=preparation,
        clock=clock,
        expected_freeze=expected_freeze,
        expected_freeze_fingerprint=freeze_fingerprint,
        final_request_result=final_request,
        final_request_receipt=request_receipt,
        kernel_execution_result=execution,
        kernel_execution_receipt=execution_receipt,
        execution_handoffs=handoffs,
        validated_graph=graph,
        result_bytes=execution.result_bytes,
        quarantined_result_sha256=None,
        stopped_envelope_fingerprint=None,
        issue_codes=(),
    )


__all__: tuple[str, ...] = ()
