"""Internal Phase 5D-5 canonical price-blind input freeze."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .component_lock import file_sha256, load_component_lock
from .contracts import ValuationAssumptionReviewDecision, ValuationHandoff
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .validation import ContractGraph, ContractGraphError
from .valuation_assumption_ledger import compile_reviewed_assumption_ledger
from .valuation_assumption_types import (
    AssumptionCandidateCompilationResult,
    AssumptionReviewRequest,
    PriceBlindReferenceClosure,
)
from .valuation_fact_mapping_policies import MAPPING_POLICY_ID, MAPPING_POLICY_VERSION
from .valuation_handoff_policies import (
    ASSUMPTION_EVIDENCE_POLICY_ID,
    ASSUMPTION_EVIDENCE_POLICY_VERSION,
    ASSUMPTION_SLOT_POLICY_ID,
    ASSUMPTION_SLOT_POLICY_VERSION,
    HANDOFF_POLICY_ID,
    HANDOFF_POLICY_VERSION,
    PRICE_BLIND_FREEZE_POLICY_ID,
    PRICE_BLIND_FREEZE_POLICY_VERSION,
    assumption_evidence_policy_sha256,
    assumption_slot_policy_sha256,
    empty_supplemental_reference_closure_sha256,
    legacy_handoff_v2_kernel_identity,
    price_blind_freeze_policy_sha256,
)
from .valuation_mckinsey_inputs import _compile_from_ledger as _compile_mckinsey
from .valuation_penman_inputs import _compile_from_ledger as _compile_penman
from .valuation_phase5c_readiness import assess_phase5c_readiness

PRICE_BLIND_INPUT_SCHEMA_VERSION = "1.0.0"
PRICE_BLIND_INPUT_FILENAME = "price-blind-input.json"

_ARTIFACT_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "issuer_id",
        "data_cutoff_date",
        "research_bundle",
        "component_lock_sha256",
        "kernel_identity",
        "mapping_policy",
        "freeze_policy",
        "supplemental_reference_closure_sha256",
        "freeze_authorization",
        "handoff_ids",
        "phase5c_readiness",
        "assumption_candidates",
        "reviewed_assumptions",
        "mckinsey_inputs",
        "penman_inputs",
        "protected_mckinsey_sha256",
        "protected_penman_assumptions_sha256",
        "price_blind_input_fingerprint",
    }
)
_FORBIDDEN_KEYS = frozenset(
    {
        "market_equity_value_fact_id",
        "market_reference_snapshot_id",
        "market_price",
        "quote_price",
        "valuation_request",
        "valuation_result",
    }
)


class PriceBlindFreezeError(ValueError):
    """Raised when the price-blind freeze cannot be replayed exactly."""


def _utc(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid date-time") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class PriceBlindFreezeAuthorization:
    """Named-human authorization for the immutable freeze and next market gate."""

    reviewer_id: str
    handoff_opened_at: str
    authorized_at: str
    rationale: str

    def __post_init__(self) -> None:
        if not self.reviewer_id.startswith("human:") or not self.reviewer_id[6:].strip():
            raise ValueError("price-blind freeze requires a named human reviewer")
        opened = _utc(self.handoff_opened_at, "handoff_opened_at")
        authorized = _utc(self.authorized_at, "authorized_at")
        if opened >= authorized:
            raise ValueError("price-blind freeze authorization is not chronological")
        if not self.rationale.strip():
            raise ValueError("price-blind freeze authorization requires a rationale")

    def to_dict(self) -> dict[str, str]:
        return {
            "reviewer_id": self.reviewer_id,
            "handoff_opened_at": _timestamp(_utc(self.handoff_opened_at, "handoff_opened_at")),
            "authorized_at": _timestamp(_utc(self.authorized_at, "authorized_at")),
            "rationale": self.rationale,
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _protected_mckinsey(payload: dict[str, Any]) -> str:
    reviewed = payload["reviewed_assumptions"]
    return canonical_sha256(
        {
            "fact_ledger": reviewed["augmented_fact_ledger_payload"],
            "assumption_ledger": reviewed["assumption_ledger_payload"],
            "phase5c_readiness": payload["phase5c_readiness"],
            "mckinsey_inputs": payload["mckinsey_inputs"],
        }
    )


def _protected_penman(payload: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "assumption_entries": payload["reviewed_assumptions"][
                "assumption_ledger_payload"
            ]["assumptions"],
            "penman_inputs": payload["penman_inputs"],
        }
    )


def _walk_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(map(_walk_keys, value.values())), set())
    if isinstance(value, (list, tuple)):
        return set().union(*(map(_walk_keys, value)), set())
    return set()


@dataclass(frozen=True, slots=True)
class PriceBlindInputArtifact:
    """Closed internal canonical artifact; deliberately not a kernel request."""

    payload: FrozenMap

    def __post_init__(self) -> None:
        payload = freeze(self.payload)
        object.__setattr__(self, "payload", payload)
        plain = to_json_value(payload)
        if set(plain) != _ARTIFACT_FIELDS:
            raise ValueError("price-blind input artifact fields are not closed")
        if (
            plain["schema_version"] != PRICE_BLIND_INPUT_SCHEMA_VERSION
            or plain["artifact_type"] != "price-blind-input"
        ):
            raise ValueError("price-blind input artifact identity is invalid")
        if _walk_keys(plain).intersection(_FORBIDDEN_KEYS):
            raise ValueError("price-blind input artifact contains market or result fields")
        if plain["protected_mckinsey_sha256"] != _protected_mckinsey(plain):
            raise ValueError("protected McKinsey hash does not replay")
        if plain["protected_penman_assumptions_sha256"] != _protected_penman(plain):
            raise ValueError("protected Penman assumption hash does not replay")
        fingerprint_payload = dict(plain)
        fingerprint = fingerprint_payload.pop("price_blind_input_fingerprint")
        if fingerprint != canonical_sha256(fingerprint_payload):
            raise ValueError("price-blind input fingerprint does not replay")
        if plain["penman_inputs"]["penman_payload"]["include_cap_diagnostic"] is not False:
            raise ValueError("price-blind Penman CAP diagnostic must remain disabled")
        assumptions = plain["reviewed_assumptions"]
        if assumptions["assumption_entries_sha256"] != canonical_sha256(
            assumptions["assumption_ledger_payload"]["assumptions"]
        ):
            raise ValueError("reviewed assumption entries do not replay")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self.payload)

    @property
    def fingerprint(self) -> str:
        return self.payload["price_blind_input_fingerprint"]


@dataclass(frozen=True, slots=True)
class PriceBlindFreezeCompilationResult:
    artifact: PriceBlindInputArtifact
    handoffs: tuple[ValuationHandoff, ...]
    candidates: tuple[Any, ...]
    decisions: tuple[ValuationAssumptionReviewDecision, ...]
    supplemental_reference_closure: PriceBlindReferenceClosure | None

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.handoffs, key=lambda item: item.handoff_version))
        object.__setattr__(self, "handoffs", ordered)
        candidates = tuple(sorted(self.candidates, key=lambda item: item.candidate_id))
        decisions = tuple(sorted(self.decisions, key=lambda item: item.decision_id))
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "decisions", decisions)
        if tuple(item.state for item in ordered) != (
            "evidence_open",
            "price_blind_candidates_reviewed",
            "price_blind_input_frozen",
            "market_reference_allowed",
        ):
            raise ValueError("price-blind freeze must contain four adjacent Handoff states")
        if tuple(self.artifact.payload["handoff_ids"]) != tuple(
            item.handoff_id for item in ordered
        ):
            raise ValueError("price-blind artifact and Handoff IDs differ")
        if set(ordered[1].assumption_candidate_ids) != {
            item.candidate_id for item in candidates
        } or set(ordered[1].assumption_review_decision_ids) != {
            item.decision_id for item in decisions
        }:
            raise ValueError("price-blind result lacks its frozen Candidate or Decision set")
        candidate_payloads = sorted(
            self.artifact.payload["assumption_candidates"]["candidates"],
            key=lambda item: item["candidate_id"],
        )
        decision_payloads = sorted(
            self.artifact.payload["reviewed_assumptions"]["decisions"],
            key=lambda item: item["decision_id"],
        )
        if [to_json_value(item) for item in candidate_payloads] != [
            item.to_dict() for item in candidates
        ] or [to_json_value(item) for item in decision_payloads] != [
            item.to_dict() for item in decisions
        ]:
            raise ValueError("price-blind artifact does not bind its typed review objects")
        expected_closure_sha256 = (
            self.supplemental_reference_closure.fingerprint
            if self.supplemental_reference_closure is not None
            else empty_supplemental_reference_closure_sha256()
        )
        if (
            self.artifact.payload["supplemental_reference_closure_sha256"]
            != expected_closure_sha256
            or any(
                item.supplemental_reference_closure_sha256 != expected_closure_sha256
                for item in candidates
            )
            or any(
                item.supplemental_reference_closure_sha256 != expected_closure_sha256
                for item in ordered
            )
        ):
            raise ValueError("price-blind supplemental reference closure does not replay")
        frozen = ordered[2]
        allowed = ordered[3]
        protected = (
            self.artifact.fingerprint,
            self.artifact.payload["protected_mckinsey_sha256"],
            self.artifact.payload["protected_penman_assumptions_sha256"],
        )
        for item in (frozen, allowed):
            if (
                item.price_blind_input_fingerprint,
                item.protected_mckinsey_sha256,
                item.protected_penman_assumptions_sha256,
            ) != protected:
                raise ValueError("Handoff does not bind the protected price-blind artifact")

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(
            {
                "artifact": self.artifact.to_dict(),
                "handoffs": [item.to_dict() for item in self.handoffs],
            }
        )


@dataclass(frozen=True, slots=True)
class PriceBlindInputArtifactReceipt:
    output_directory: Path
    artifact_path: Path
    file_sha256: str
    price_blind_input_fingerprint: str


def _active_confirmed_decisions(ledger_result: Any, candidate_result: Any) -> tuple[Any, ...]:
    superseded = {
        item.supersedes_decision_id
        for item in ledger_result.decisions
        if item.supersedes_decision_id is not None
    }
    active = tuple(item for item in ledger_result.decisions if item.decision_id not in superseded)
    by_candidate: dict[str, list[Any]] = {}
    for item in active:
        by_candidate.setdefault(item.candidate_id, []).append(item)
    candidate_ids = {item.candidate_id for item in candidate_result.candidates}
    if set(by_candidate) != candidate_ids or any(
        len(items) != 1
        or items[0].decision != "confirmed"
        or items[0].reserved_kernel_assumption_id is None
        for items in by_candidate.values()
    ):
        raise PriceBlindFreezeError(
            "every price-blind Candidate requires one active confirmed named-human Decision"
        )
    return tuple(
        sorted(
            (items[0] for items in by_candidate.values()),
            key=lambda item: item.decision_id,
        )
    )


def _merge_contracts(
    existing: tuple[Any, ...], additions: tuple[Any, ...], id_field: str
) -> tuple[Any, ...]:
    merged = {getattr(item, id_field): item for item in existing}
    if len(merged) != len(existing):
        raise PriceBlindFreezeError(f"existing {id_field} values are not unique")
    for item in additions:
        identifier = getattr(item, id_field)
        prior = merged.get(identifier)
        if prior is not None and prior.fingerprint != item.fingerprint:
            raise PriceBlindFreezeError(f"{id_field} collision changed immutable content")
        merged[identifier] = item
    return tuple(merged[key] for key in sorted(merged))


def _handoff_run_digest(
    *,
    bundle: Any,
    candidate_result: Any,
    decisions: tuple[Any, ...],
    authorization: PriceBlindFreezeAuthorization,
) -> str:
    return canonical_sha256(
        {
            "issuer_id": bundle.issuer_id,
            "data_cutoff_date": bundle.data_cutoff_date,
            "research_bundle_fingerprint": bundle.bundle_fingerprint,
            "candidate_compilation_fingerprint": candidate_result.fingerprint,
            "decision_fingerprints": [
                item.fingerprint
                for item in sorted(decisions, key=lambda value: value.decision_id)
            ],
            "authorization": authorization.to_dict(),
        }
    )


def _handoff_chain(
    *,
    graph: ContractGraph,
    bundle: Any,
    candidate_result: Any,
    ledger_result: Any,
    authorization: PriceBlindFreezeAuthorization,
    artifact_fingerprint: str,
    protected_mckinsey_sha256: str,
    protected_penman_sha256: str,
) -> tuple[ValuationHandoff, ...]:
    active = _active_confirmed_decisions(ledger_result, candidate_result)
    all_decisions = tuple(sorted(ledger_result.decisions, key=lambda item: item.decision_id))
    reviewed_times = tuple(_utc(item.reviewed_at, "Decision reviewed_at") for item in active)
    opened_at = _utc(authorization.handoff_opened_at, "handoff_opened_at")
    reviewed_at = max(reviewed_times)
    frozen_at = _utc(authorization.authorized_at, "authorized_at")
    if opened_at >= min(reviewed_times) or reviewed_at >= frozen_at:
        raise PriceBlindFreezeError(
            "Handoff evidence, review, and freeze times are not chronological"
        )
    allowed_at = frozen_at + timedelta(microseconds=1)
    run_digest = _handoff_run_digest(
        bundle=bundle,
        candidate_result=candidate_result,
        decisions=all_decisions,
        authorization=authorization,
    )
    run_id = f"valuation-handoff-run:{bundle.issuer_id}:{run_digest[:20]}"
    ids = tuple(
        f"valuation-handoff:{bundle.issuer_id}:{run_digest[:20]}:v{index}"
        for index in range(1, 5)
    )
    common = {
        "schema_version": "2.0.0",
        "handoff_policy_id": HANDOFF_POLICY_ID,
        "handoff_policy_version": HANDOFF_POLICY_VERSION,
        "handoff_run_id": run_id,
        "issuer_id": bundle.issuer_id,
        "data_cutoff_date": bundle.data_cutoff_date,
        "supersedes_handoff_id": None,
        "research_bundle_id": bundle.bundle_id,
        "research_bundle_fingerprint": bundle.bundle_fingerprint,
        "research_bundle_dependency_sha256": bundle.dependency_closure_sha256,
        "research_run_manifest_id": bundle.run_id,
        "supplemental_reference_closure_sha256": (
            candidate_result.supplemental_reference_closure_sha256
        ),
        "mapping_policy_id": MAPPING_POLICY_ID,
        "mapping_policy_version": MAPPING_POLICY_VERSION,
        "assumption_slot_policy_id": ASSUMPTION_SLOT_POLICY_ID,
        "assumption_slot_policy_version": ASSUMPTION_SLOT_POLICY_VERSION,
        "assumption_slot_policy_sha256": assumption_slot_policy_sha256(),
        "assumption_evidence_policy_id": ASSUMPTION_EVIDENCE_POLICY_ID,
        "assumption_evidence_policy_version": ASSUMPTION_EVIDENCE_POLICY_VERSION,
        "assumption_evidence_policy_sha256": assumption_evidence_policy_sha256(),
        "price_blind_freeze_policy_id": PRICE_BLIND_FREEZE_POLICY_ID,
        "price_blind_freeze_policy_version": PRICE_BLIND_FREEZE_POLICY_VERSION,
        "price_blind_freeze_policy_sha256": price_blind_freeze_policy_sha256(),
        "component_lock_sha256": file_sha256(graph.component_lock_path),
        "kernel_identity": legacy_handoff_v2_kernel_identity(),
        "market_reference_snapshot_id": None,
        "valuation_request_sha256": None,
        "valuation_result_sha256": None,
        "quarantined_market_reference_snapshot_ids": (),
    }
    root = ValuationHandoff(
        **common,
        handoff_id=ids[0],
        handoff_version=1,
        transitioned_at=_timestamp(opened_at),
        state="evidence_open",
        predecessor_handoff_id=None,
        assumption_candidate_ids=(),
        assumption_review_decision_ids=(),
        price_blind_input_fingerprint=None,
        protected_mckinsey_sha256=None,
        protected_penman_assumptions_sha256=None,
        missing_evidence=("Price-blind Candidates have not been reviewed.",),
    )
    reviewed = ValuationHandoff(
        **common,
        handoff_id=ids[1],
        handoff_version=2,
        transitioned_at=_timestamp(reviewed_at),
        state="price_blind_candidates_reviewed",
        predecessor_handoff_id=root.handoff_id,
        assumption_candidate_ids=tuple(
            sorted(item.candidate_id for item in candidate_result.candidates)
        ),
        assumption_review_decision_ids=tuple(item.decision_id for item in all_decisions),
        price_blind_input_fingerprint=None,
        protected_mckinsey_sha256=None,
        protected_penman_assumptions_sha256=None,
        missing_evidence=("Canonical price-blind input has not been frozen.",),
    )
    frozen = replace(
        reviewed,
        handoff_id=ids[2],
        handoff_version=3,
        transitioned_at=_timestamp(frozen_at),
        state="price_blind_input_frozen",
        predecessor_handoff_id=reviewed.handoff_id,
        price_blind_input_fingerprint=artifact_fingerprint,
        protected_mckinsey_sha256=protected_mckinsey_sha256,
        protected_penman_assumptions_sha256=protected_penman_sha256,
        missing_evidence=(),
    )
    allowed = replace(
        frozen,
        handoff_id=ids[3],
        handoff_version=4,
        transitioned_at=_timestamp(allowed_at),
        state="market_reference_allowed",
        predecessor_handoff_id=frozen.handoff_id,
    )
    return root, reviewed, frozen, allowed


def _validated_graph(
    graph: ContractGraph,
    *,
    candidate_result: Any,
    ledger_result: Any,
    handoffs: tuple[ValuationHandoff, ...],
    supplemental_reference_closure: PriceBlindReferenceClosure | None,
) -> ContractGraph:
    closures = graph.price_blind_reference_closures
    if supplemental_reference_closure is not None:
        closures = _merge_contracts(
            closures,
            (supplemental_reference_closure,),
            "closure_id",
        )
    candidate_graph = replace(
        graph,
        price_blind_reference_closures=closures,
        valuation_assumption_candidates=_merge_contracts(
            graph.valuation_assumption_candidates,
            tuple(candidate_result.candidates),
            "candidate_id",
        ),
        valuation_assumption_review_decisions=_merge_contracts(
            graph.valuation_assumption_review_decisions,
            tuple(ledger_result.decisions),
            "decision_id",
        ),
        valuation_handoffs=_merge_contracts(
            graph.valuation_handoffs,
            handoffs,
            "handoff_id",
        ),
    )
    try:
        candidate_graph.validate()
    except ContractGraphError as exc:
        raise PriceBlindFreezeError("frozen Handoff chain does not replay") from exc
    return candidate_graph


def compile_price_blind_input_freeze(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
    candidate_result: AssumptionCandidateCompilationResult,
    review_requests: tuple[AssumptionReviewRequest, ...],
    freeze_authorization: PriceBlindFreezeAuthorization,
    supplemental_reference_closure: PriceBlindReferenceClosure | None = None,
    prior_decisions: tuple[ValuationAssumptionReviewDecision, ...] = (),
) -> PriceBlindFreezeCompilationResult:
    """Replay the accepted chain and freeze one canonical nonmarket input artifact."""

    ledger = compile_reviewed_assumption_ledger(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
        candidate_result=candidate_result,
        review_requests=review_requests,
        supplemental_reference_closure=supplemental_reference_closure,
        prior_decisions=prior_decisions,
    )
    readiness = assess_phase5c_readiness(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
    )
    if readiness.fingerprint != ledger.phase5c_readiness_fingerprint:
        raise PriceBlindFreezeError("Phase 5C readiness changed during the freeze replay")
    mckinsey = _compile_mckinsey(
        kernel_repository=Path(kernel_repository),
        candidate_result=candidate_result,
        ledger_result=ledger,
    )
    penman = _compile_penman(
        kernel_repository=Path(kernel_repository),
        candidate_result=candidate_result,
        ledger_result=ledger,
    )
    bundle = next(
        (
            item
            for item in graph.research_bundles
            if item.bundle_id == ledger.research_bundle_id
            and item.bundle_fingerprint == ledger.research_bundle_fingerprint
        ),
        None,
    )
    if bundle is None:
        raise PriceBlindFreezeError("reviewed assumptions lack the exact ResearchBundle")
    active = _active_confirmed_decisions(ledger, candidate_result)
    reviewed_at = max(_utc(item.reviewed_at, "Decision reviewed_at") for item in active)
    opened_at = _utc(freeze_authorization.handoff_opened_at, "handoff_opened_at")
    frozen_at = _utc(freeze_authorization.authorized_at, "authorized_at")
    if not opened_at < reviewed_at < frozen_at:
        raise PriceBlindFreezeError("freeze authorization does not follow named-human review")
    run_digest = _handoff_run_digest(
        bundle=bundle,
        candidate_result=candidate_result,
        decisions=tuple(ledger.decisions),
        authorization=freeze_authorization,
    )
    handoff_ids = [
        f"valuation-handoff:{bundle.issuer_id}:{run_digest[:20]}:v{index}"
        for index in range(1, 5)
    ]
    lock = load_component_lock(graph.component_lock_path)
    base_payload: dict[str, Any] = {
        "schema_version": PRICE_BLIND_INPUT_SCHEMA_VERSION,
        "artifact_type": "price-blind-input",
        "issuer_id": bundle.issuer_id,
        "data_cutoff_date": bundle.data_cutoff_date,
        "research_bundle": {
            "bundle_id": bundle.bundle_id,
            "bundle_fingerprint": bundle.bundle_fingerprint,
            "dependency_closure_sha256": bundle.dependency_closure_sha256,
            "run_manifest_id": bundle.run_id,
        },
        "component_lock_sha256": file_sha256(graph.component_lock_path),
        "kernel_identity": lock["valuation_kernel"],
        "mapping_policy": {
            "policy_id": MAPPING_POLICY_ID,
            "policy_version": MAPPING_POLICY_VERSION,
        },
        "freeze_policy": {
            "policy_id": PRICE_BLIND_FREEZE_POLICY_ID,
            "policy_version": PRICE_BLIND_FREEZE_POLICY_VERSION,
            "policy_sha256": price_blind_freeze_policy_sha256(),
        },
        "supplemental_reference_closure_sha256": ledger.supplemental_reference_closure_sha256,
        "freeze_authorization": freeze_authorization.to_dict(),
        "handoff_ids": handoff_ids,
        "phase5c_readiness": readiness.to_dict(),
        "assumption_candidates": candidate_result.to_dict(),
        "reviewed_assumptions": ledger.to_dict(),
        "mckinsey_inputs": mckinsey.to_dict(),
        "penman_inputs": penman.to_dict(),
    }
    base_payload["protected_mckinsey_sha256"] = _protected_mckinsey(base_payload)
    base_payload["protected_penman_assumptions_sha256"] = _protected_penman(base_payload)
    base_payload["price_blind_input_fingerprint"] = canonical_sha256(base_payload)
    artifact = PriceBlindInputArtifact(payload=base_payload)
    handoffs = _handoff_chain(
        graph=graph,
        bundle=bundle,
        candidate_result=candidate_result,
        ledger_result=ledger,
        authorization=freeze_authorization,
        artifact_fingerprint=artifact.fingerprint,
        protected_mckinsey_sha256=artifact.payload["protected_mckinsey_sha256"],
        protected_penman_sha256=artifact.payload["protected_penman_assumptions_sha256"],
    )
    if tuple(handoff_ids) != tuple(item.handoff_id for item in handoffs):
        raise PriceBlindFreezeError("derived Handoff identity changed during compilation")
    _validated_graph(
        graph,
        candidate_result=candidate_result,
        ledger_result=ledger,
        handoffs=handoffs,
        supplemental_reference_closure=supplemental_reference_closure,
    )
    return PriceBlindFreezeCompilationResult(
        artifact=artifact,
        handoffs=handoffs,
        candidates=tuple(candidate_result.candidates),
        decisions=tuple(ledger.decisions),
        supplemental_reference_closure=supplemental_reference_closure,
    )


def _reject_symlink_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise PriceBlindFreezeError("price-blind artifact path cannot contain a symlink")


def _artifact_bytes(result: PriceBlindFreezeCompilationResult) -> bytes:
    return (canonical_json(result.artifact.to_dict()) + "\n").encode("utf-8")


def _validate_existing_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PriceBlindFreezeError("price-blind artifact directory is unsafe")
    entries = tuple(path.iterdir())
    if any(item.is_symlink() or not item.is_file() for item in entries):
        raise PriceBlindFreezeError("price-blind artifact directory contains an unsafe entry")
    if {item.name for item in entries} != {PRICE_BLIND_INPUT_FILENAME}:
        raise PriceBlindFreezeError("price-blind artifact directory must contain exactly one file")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_price_blind_input_artifact(
    graph: ContractGraph,
    result: PriceBlindFreezeCompilationResult,
    *,
    output_directory: Path,
    overwrite: bool = False,
) -> PriceBlindInputArtifactReceipt:
    """Atomically write exactly one canonical internal price-blind input file."""

    # Reconstructing the result replays its hashes and Handoff bindings.
    result = PriceBlindFreezeCompilationResult(
        result.artifact,
        result.handoffs,
        result.candidates,
        result.decisions,
        result.supplemental_reference_closure,
    )
    closures = graph.price_blind_reference_closures
    if result.supplemental_reference_closure is not None:
        closures = _merge_contracts(
            closures,
            (result.supplemental_reference_closure,),
            "closure_id",
        )
    replay_graph = replace(
        graph,
        price_blind_reference_closures=closures,
        valuation_assumption_candidates=_merge_contracts(
            graph.valuation_assumption_candidates, result.candidates, "candidate_id"
        ),
        valuation_assumption_review_decisions=_merge_contracts(
            graph.valuation_assumption_review_decisions, result.decisions, "decision_id"
        ),
        valuation_handoffs=_merge_contracts(
            graph.valuation_handoffs, result.handoffs, "handoff_id"
        ),
    )
    try:
        replay_graph.validate()
    except ContractGraphError as exc:
        raise PriceBlindFreezeError("writer graph cannot replay the frozen Handoff chain") from exc
    target = Path(output_directory).expanduser().absolute()
    if not target.name or target == target.parent:
        raise PriceBlindFreezeError("price-blind artifact output directory is unsafe")
    _reject_symlink_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_path(target)
    content = _artifact_bytes(result)
    if target.exists() or target.is_symlink():
        _validate_existing_directory(target)
        existing = (target / PRICE_BLIND_INPUT_FILENAME).read_bytes()
        if existing == content:
            return PriceBlindInputArtifactReceipt(
                target,
                target / PRICE_BLIND_INPUT_FILENAME,
                hashlib.sha256(content).hexdigest(),
                result.artifact.fingerprint,
            )
        if not overwrite:
            raise PriceBlindFreezeError("price-blind artifact exists with different content")
    staging = target.parent / f".{target.name}.staging-{uuid.uuid4().hex}"
    backup: Path | None = None
    try:
        staging.mkdir(mode=0o700)
        artifact_path = staging / PRICE_BLIND_INPUT_FILENAME
        with artifact_path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(staging)
        if target.exists():
            backup = target.parent / f".{target.name}.backup-{uuid.uuid4().hex}"
            target.rename(backup)
        staging.rename(target)
        _fsync_directory(target.parent)
        if backup is not None:
            shutil.rmtree(backup)
            _fsync_directory(target.parent)
    except OSError as exc:
        if backup is not None and backup.exists() and not target.exists():
            backup.rename(target)
            _fsync_directory(target.parent)
        raise PriceBlindFreezeError(f"price-blind artifact publication failed: {exc}") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return PriceBlindInputArtifactReceipt(
        target,
        target / PRICE_BLIND_INPUT_FILENAME,
        hashlib.sha256(content).hexdigest(),
        result.artifact.fingerprint,
    )


def load_price_blind_input_artifact(
    input_directory: Path,
    *,
    graph: ContractGraph,
    expected_result: PriceBlindFreezeCompilationResult,
) -> PriceBlindFreezeCompilationResult:
    """Strictly reload canonical bytes against the fully replayed expected freeze."""

    source = Path(input_directory).expanduser().absolute()
    _reject_symlink_path(source)
    _validate_existing_directory(source)
    path = source / PRICE_BLIND_INPUT_FILENAME
    try:
        payload = json.loads(path.read_text("utf-8"))
        artifact = PriceBlindInputArtifact(payload=payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PriceBlindFreezeError(f"price-blind artifact payload is invalid: {exc}") from exc
    loaded = PriceBlindFreezeCompilationResult(
        artifact,
        expected_result.handoffs,
        expected_result.candidates,
        expected_result.decisions,
        expected_result.supplemental_reference_closure,
    )
    if loaded.fingerprint != expected_result.fingerprint:
        raise PriceBlindFreezeError("price-blind artifact differs from the replayed freeze")
    expected = _artifact_bytes(expected_result)
    if path.read_bytes() != expected:
        raise PriceBlindFreezeError("price-blind artifact is not canonically serialized")
    closures = graph.price_blind_reference_closures
    if loaded.supplemental_reference_closure is not None:
        closures = _merge_contracts(
            closures,
            (loaded.supplemental_reference_closure,),
            "closure_id",
        )
    replay_graph = replace(
        graph,
        price_blind_reference_closures=closures,
        valuation_assumption_candidates=_merge_contracts(
            graph.valuation_assumption_candidates, loaded.candidates, "candidate_id"
        ),
        valuation_assumption_review_decisions=_merge_contracts(
            graph.valuation_assumption_review_decisions, loaded.decisions, "decision_id"
        ),
        valuation_handoffs=_merge_contracts(
            graph.valuation_handoffs, loaded.handoffs, "handoff_id"
        ),
    )
    try:
        replay_graph.validate()
    except ContractGraphError as exc:
        raise PriceBlindFreezeError("loaded price-blind Handoff chain does not replay") from exc
    return loaded


__all__ = ()
