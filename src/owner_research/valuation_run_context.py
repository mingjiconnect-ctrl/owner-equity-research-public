"""Canonical bridge from an in-memory trusted graph to the explicit valuation CLI."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .component_lock import default_component_lock_path
from .contracts import Contract, contract_from_dict
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze
from .validation import ContractGraph, ContractGraphError
from .valuation_assumption_types import (
    AssumptionCandidateProposal,
    AssumptionEvidenceRequest,
    AssumptionReviewRequest,
    PriceBlindReferenceClosure,
)
from .valuation_handoff_policies import empty_supplemental_reference_closure_sha256
from .valuation_market_provider import RunClock
from .valuation_owner_execution import OwnerValuationExecutionClock
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindInputArtifact,
)
from .valuation_run import ValuationRunClock
from .valuation_security_identity import (
    SecurityAccessProposal,
    SecurityFactBinding,
    SecurityIdentityCompilationResult,
    compile_security_identity,
)

VALUATION_RUN_INPUT_FILENAME = "valuation-run-input.json"
CORE_JSON_MAX_BYTES = 16 * 1024 * 1024
RESEARCH_INPUT_FILE_MAX_BYTES = 64 * 1024 * 1024
RESEARCH_INPUT_TOTAL_MAX_BYTES = 256 * 1024 * 1024
_CONTEXT_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "component_lock_sha256",
        "graph_collections",
        "research_bundle_artifacts",
        "price_blind_input_fingerprint",
        "expected_freeze_fingerprint",
        "security_proposal",
        "expected_security_fingerprint",
        "assumption_proposals",
        "assumption_reviews",
        "clock",
        "context_fingerprint",
    }
)
_GRAPH_FIELDS = tuple(
    field.name for field in fields(ContractGraph) if field.name != "component_lock_path"
)


class ValuationRunContextError(ValueError):
    """The CLI context cannot reconstruct the exact in-memory valuation authority."""


@dataclass(frozen=True, slots=True)
class ValuationRunInputContext:
    graph: ContractGraph
    expected_freeze: PriceBlindFreezeCompilationResult
    expected_security: SecurityIdentityCompilationResult
    assumption_proposals: tuple[AssumptionCandidateProposal, ...]
    assumption_reviews: tuple[AssumptionReviewRequest, ...]
    clock: ValuationRunClock
    research_bundle_contents: FrozenMap
    context_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "assumption_proposals", tuple(self.assumption_proposals))
        object.__setattr__(self, "assumption_reviews", tuple(self.assumption_reviews))
        object.__setattr__(self, "research_bundle_contents", freeze(self.research_bundle_contents))
        if type(self.graph) is not ContractGraph:
            raise ValueError("valuation run context requires an exact ContractGraph")
        if type(self.expected_freeze) is not PriceBlindFreezeCompilationResult:
            raise ValueError("valuation run context requires an exact price-blind freeze")
        if type(self.expected_security) is not SecurityIdentityCompilationResult:
            raise ValueError("valuation run context requires an exact security compilation")
        if type(self.clock) is not ValuationRunClock:
            raise ValueError("valuation run context requires an exact clock")
        if (
            type(self.context_fingerprint) is not str
            or len(self.context_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.context_fingerprint)
        ):
            raise ValueError("valuation run context fingerprint is invalid")
        expected_fingerprint = canonical_sha256(
            _replayed_context_payload(
                graph=self.graph,
                expected_freeze=self.expected_freeze,
                expected_security=self.expected_security,
                assumption_proposals=self.assumption_proposals,
                assumption_reviews=self.assumption_reviews,
                clock=self.clock,
                research_bundle_contents=self.research_bundle_contents,
            )
        )
        if self.context_fingerprint != expected_fingerprint:
            raise ValueError("valuation run context fingerprint does not replay typed inputs")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_file(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValuationRunContextError(f"valuation run input repeats key {key!r}")
        output[key] = value
    return output


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    absolute = Path(path).expanduser().absolute()
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ValuationRunContextError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValuationRunContextError(f"{label} is not one bounded regular file")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValuationRunContextError(f"{label} exceeds the byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or consumed != before.st_size:
            raise ValuationRunContextError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValuationRunContextError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValuationRunContextError(f"{label} must be a JSON object")
    return payload


def _bounded_sha256(path: Path, label: str, maximum: int) -> str:
    return _sha256(_read_regular(path, label, maximum))


def _graph_payload(graph: ContractGraph) -> dict[str, list[dict[str, Any]]]:
    graph.validate()
    if graph.market_reference_validation_contexts:
        raise ValuationRunContextError(
            "valuation CLI context must be frozen before market validation contexts exist"
        )
    output: dict[str, list[dict[str, Any]]] = {}
    for name in _GRAPH_FIELDS:
        items: list[dict[str, Any]] = []
        for item in getattr(graph, name):
            if isinstance(item, Contract):
                items.append(
                    {
                        "kind": "public_contract",
                        "schema_name": item.SCHEMA_NAME,
                        "payload": item.to_dict(),
                    }
                )
            elif type(item) is PriceBlindReferenceClosure:
                items.append(
                    {
                        "kind": "price_blind_reference_closure",
                        "payload": item.to_dict(),
                    }
                )
            else:
                raise ValuationRunContextError(
                    f"graph collection {name} contains an unregistered context object"
                )
        output[name] = items
    return output


def _load_graph(payload: Any) -> ContractGraph:
    if not isinstance(payload, dict) or set(payload) != set(_GRAPH_FIELDS):
        raise ValuationRunContextError("valuation run graph fields are not closed")
    values: dict[str, tuple[Any, ...]] = {}
    for name in _GRAPH_FIELDS:
        records = payload[name]
        if not isinstance(records, list):
            raise ValuationRunContextError(f"graph collection {name} is not an array")
        items: list[Any] = []
        for record in records:
            if not isinstance(record, dict):
                raise ValuationRunContextError(f"graph collection {name} has an invalid record")
            if record.get("kind") == "public_contract" and set(record) == {
                "kind",
                "schema_name",
                "payload",
            }:
                try:
                    items.append(contract_from_dict(record["schema_name"], record["payload"]))
                except Exception as exc:
                    raise ValuationRunContextError(
                        f"graph collection {name} has an invalid public contract"
                    ) from exc
            elif record.get("kind") == "price_blind_reference_closure" and set(record) == {
                "kind",
                "payload",
            }:
                try:
                    items.append(PriceBlindReferenceClosure(**record["payload"]))
                except (TypeError, ValueError) as exc:
                    raise ValuationRunContextError(
                        "price-blind reference closure does not replay"
                    ) from exc
            else:
                raise ValuationRunContextError(
                    f"graph collection {name} has an unregistered record kind"
                )
        values[name] = tuple(items)
    graph = ContractGraph(**values, component_lock_path=default_component_lock_path())
    try:
        graph.validate()
    except ContractGraphError as exc:
        raise ValuationRunContextError("valuation run ContractGraph does not replay") from exc
    return graph


def _research_bundle_payload(directory: Path) -> dict[str, Any]:
    source = Path(directory).expanduser().absolute()
    files = {
        "research-bundle.json": _read_regular(
            source / "research-bundle.json",
            "research Bundle",
            RESEARCH_INPUT_FILE_MAX_BYTES,
        ),
        "run-manifest.json": _read_regular(
            source / "run-manifest.json",
            "research manifest",
            RESEARCH_INPUT_FILE_MAX_BYTES,
        ),
    }
    if sum(len(content) for content in files.values()) > RESEARCH_INPUT_TOTAL_MAX_BYTES:
        raise ValuationRunContextError("research inputs exceed the cumulative byte limit")
    payload: dict[str, Any] = {}
    for name, content in files.items():
        value = _json_object(content, name)
        if content != _canonical_file(value):
            raise ValuationRunContextError(f"{name} is not canonically serialized")
        payload[name] = {"payload": value, "sha256": _sha256(content)}
    return payload


def _validate_research_bundle_payload(
    graph: ContractGraph,
    payload: dict[str, Any],
) -> None:
    bundle_payload = payload["research-bundle.json"]["payload"]
    manifest_payload = payload["run-manifest.json"]["payload"]
    matching_bundles = tuple(
        item for item in graph.research_bundles if item.to_dict() == bundle_payload
    )
    matching_manifests = tuple(
        item for item in graph.manifests if item.to_dict() == manifest_payload
    )
    if len(matching_bundles) != 1 or len(matching_manifests) != 1:
        raise ValuationRunContextError(
            "research Bundle artifacts do not identify exact graph contracts"
        )
    if matching_bundles[0].run_id != matching_manifests[0].run_id:
        raise ValuationRunContextError("research Bundle artifacts belong to different runs")


def _replayed_context_payload(
    *,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    assumption_proposals: tuple[AssumptionCandidateProposal, ...],
    assumption_reviews: tuple[AssumptionReviewRequest, ...],
    clock: ValuationRunClock,
    research_bundle_contents: FrozenMap,
) -> dict[str, Any]:
    names = ("research-bundle.json", "run-manifest.json")
    if set(research_bundle_contents) != set(names):
        raise ValueError("valuation run context research artifact set is not closed")
    artifacts: dict[str, Any] = {}
    total = 0
    for name in names:
        raw = research_bundle_contents[name]
        if type(raw) is not bytes or len(raw) > RESEARCH_INPUT_FILE_MAX_BYTES:
            raise ValueError("valuation run context research artifact is not bounded bytes")
        total += len(raw)
        payload = _json_object(raw, name)
        if raw != _canonical_file(payload):
            raise ValueError("valuation run context research artifact is not canonical")
        artifacts[name] = {"payload": payload, "sha256": _sha256(raw)}
    if total > RESEARCH_INPUT_TOTAL_MAX_BYTES:
        raise ValueError("valuation run context research artifacts exceed the cumulative limit")
    _validate_research_bundle_payload(graph, artifacts)
    return {
        "schema_version": "1.0.0",
        "artifact_type": "valuation-run-input",
        "component_lock_sha256": _bounded_sha256(
            graph.component_lock_path,
            "component lock",
            CORE_JSON_MAX_BYTES,
        ),
        "graph_collections": _graph_payload(graph),
        "research_bundle_artifacts": artifacts,
        "price_blind_input_fingerprint": expected_freeze.artifact.fingerprint,
        "expected_freeze_fingerprint": expected_freeze.fingerprint,
        "security_proposal": _security_proposal_payload(expected_security.proposal),
        "expected_security_fingerprint": expected_security.fingerprint,
        "assumption_proposals": [item.to_dict() for item in assumption_proposals],
        "assumption_reviews": [item.to_dict() for item in assumption_reviews],
        "clock": clock.to_dict(),
    }


def _security_proposal_payload(proposal: SecurityAccessProposal) -> dict[str, Any]:
    return proposal.to_dict()


def _assumption_proposal(payload: dict[str, Any]) -> AssumptionCandidateProposal:
    try:
        evidence = tuple(AssumptionEvidenceRequest(**item) for item in payload["evidence"])
        return AssumptionCandidateProposal(
            **{key: value for key, value in payload.items() if key != "evidence"},
            evidence=evidence,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValuationRunContextError("assumption proposal does not replay") from exc


def _security_proposal(payload: dict[str, Any]) -> SecurityAccessProposal:
    try:
        bindings = tuple(SecurityFactBinding(**item) for item in payload["fact_bindings"])
        return SecurityAccessProposal(
            **{key: value for key, value in payload.items() if key != "fact_bindings"},
            fact_bindings=bindings,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValuationRunContextError("security proposal does not replay") from exc


def _freeze_from_graph(
    *, graph: ContractGraph, artifact: PriceBlindInputArtifact
) -> PriceBlindFreezeCompilationResult:
    artifact_payload = artifact.to_dict()
    handoff_index = {item.handoff_id: item for item in graph.valuation_handoffs}
    candidate_index = {item.candidate_id: item for item in graph.valuation_assumption_candidates}
    decision_index = {
        item.decision_id: item for item in graph.valuation_assumption_review_decisions
    }
    try:
        handoffs = tuple(handoff_index[item] for item in artifact_payload["handoff_ids"])
        candidates = tuple(
            candidate_index[item["candidate_id"]]
            for item in artifact_payload["assumption_candidates"]["candidates"]
        )
        decisions = tuple(
            decision_index[item["decision_id"]]
            for item in artifact_payload["reviewed_assumptions"]["decisions"]
        )
    except KeyError as exc:
        raise ValuationRunContextError("price-blind graph omits frozen review objects") from exc
    closure_sha = artifact_payload["supplemental_reference_closure_sha256"]
    matching_closures = tuple(
        item for item in graph.price_blind_reference_closures if item.fingerprint == closure_sha
    )
    if closure_sha == empty_supplemental_reference_closure_sha256():
        if matching_closures:
            raise ValuationRunContextError("empty supplemental closure is not canonical")
        closure = None
    elif len(matching_closures) == 1:
        closure = matching_closures[0]
    else:
        raise ValuationRunContextError("supplemental reference closure does not replay")
    try:
        return PriceBlindFreezeCompilationResult(
            artifact=artifact,
            handoffs=handoffs,
            candidates=candidates,
            decisions=decisions,
            supplemental_reference_closure=closure,
        )
    except ValueError as exc:
        raise ValuationRunContextError("price-blind freeze does not replay") from exc


def _context_payload(
    *,
    graph: ContractGraph,
    bundle_artifact_directory: Path,
    expected_freeze: PriceBlindFreezeCompilationResult,
    security_proposal: SecurityAccessProposal,
    assumption_proposals: tuple[AssumptionCandidateProposal, ...],
    assumption_reviews: tuple[AssumptionReviewRequest, ...],
    clock: ValuationRunClock,
) -> dict[str, Any]:
    security = compile_security_identity(
        graph=graph,
        expected_freeze=expected_freeze,
        proposal=security_proposal,
    )
    if security.status not in {"eligible", "specialist_required", "blocked"}:
        raise ValuationRunContextError("security compilation status is invalid")
    research_artifacts = _research_bundle_payload(bundle_artifact_directory)
    _validate_research_bundle_payload(graph, research_artifacts)
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_type": "valuation-run-input",
        "component_lock_sha256": _bounded_sha256(
            graph.component_lock_path,
            "component lock",
            CORE_JSON_MAX_BYTES,
        ),
        "graph_collections": _graph_payload(graph),
        "research_bundle_artifacts": research_artifacts,
        "price_blind_input_fingerprint": expected_freeze.artifact.fingerprint,
        "expected_freeze_fingerprint": expected_freeze.fingerprint,
        "security_proposal": _security_proposal_payload(security_proposal),
        "expected_security_fingerprint": security.fingerprint,
        "assumption_proposals": [item.to_dict() for item in assumption_proposals],
        "assumption_reviews": [item.to_dict() for item in assumption_reviews],
        "clock": clock.to_dict(),
    }
    payload["context_fingerprint"] = canonical_sha256(payload)
    return payload


def write_valuation_run_input_context(
    *,
    graph: ContractGraph,
    bundle_artifact_directory: Path,
    expected_freeze: PriceBlindFreezeCompilationResult,
    security_proposal: SecurityAccessProposal,
    assumption_proposals: tuple[AssumptionCandidateProposal, ...],
    assumption_reviews: tuple[AssumptionReviewRequest, ...],
    clock: ValuationRunClock,
    output_file: Path,
    overwrite: bool = False,
) -> Path:
    """Atomically write one canonical CLI input without market or kernel-result bytes."""

    payload = _context_payload(
        graph=graph,
        bundle_artifact_directory=bundle_artifact_directory,
        expected_freeze=expected_freeze,
        security_proposal=security_proposal,
        assumption_proposals=tuple(assumption_proposals),
        assumption_reviews=tuple(assumption_reviews),
        clock=clock,
    )
    content = _canonical_file(payload)
    if len(content) > CORE_JSON_MAX_BYTES:
        raise ValuationRunContextError("valuation run input exceeds the byte limit")
    target = Path(output_file).expanduser().absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValuationRunContextError("valuation run input cannot be a symlink")
    if target.exists():
        existing = _read_regular(target, "valuation run input", CORE_JSON_MAX_BYTES)
        if existing == content:
            return target
        raise ValuationRunContextError("valuation run input exists with different content")
    temporary = target.parent / f".{target.name}.staging-{uuid.uuid4().hex}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ValuationRunContextError("valuation run input write did not complete")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as exc:
            existing = _read_regular(target, "valuation run input", CORE_JSON_MAX_BYTES)
            if existing != content:
                raise ValuationRunContextError(
                    "valuation run input exists with different content"
                ) from exc
        os.unlink(temporary)
        parent_descriptor = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise ValuationRunContextError(f"valuation run input publication failed: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
    return target


def load_valuation_run_input_context(
    input_file: Path,
    *,
    price_blind_artifact_directory: Path,
) -> ValuationRunInputContext:
    """Strictly reconstruct graph, freeze, security, assumptions, and clocks."""

    content = _read_regular(input_file, "valuation run input", CORE_JSON_MAX_BYTES)
    payload = _json_object(content, "valuation run input")
    if content != _canonical_file(payload):
        raise ValuationRunContextError("valuation run input is not canonically serialized")
    if set(payload) != _CONTEXT_FIELDS:
        raise ValuationRunContextError("valuation run input fields are not closed")
    if payload["schema_version"] != "1.0.0" or payload["artifact_type"] != "valuation-run-input":
        raise ValuationRunContextError("valuation run input identity is invalid")
    supplied_fingerprint = payload["context_fingerprint"]
    fingerprint_payload = dict(payload)
    fingerprint_payload.pop("context_fingerprint")
    if supplied_fingerprint != canonical_sha256(fingerprint_payload):
        raise ValuationRunContextError("valuation run input fingerprint does not replay")
    graph = _load_graph(payload["graph_collections"])
    if payload["component_lock_sha256"] != _bounded_sha256(
        graph.component_lock_path,
        "component lock",
        CORE_JSON_MAX_BYTES,
    ):
        raise ValuationRunContextError("valuation run input component lock changed")
    artifact_path = Path(price_blind_artifact_directory) / "price-blind-input.json"
    artifact_content = _read_regular(
        artifact_path,
        "price-blind input",
        CORE_JSON_MAX_BYTES,
    )
    artifact_payload = _json_object(artifact_content, "price-blind input")
    if artifact_content != _canonical_file(artifact_payload):
        raise ValuationRunContextError("price-blind artifact is not canonically serialized")
    try:
        artifact = PriceBlindInputArtifact(artifact_payload)
        freeze_result = _freeze_from_graph(graph=graph, artifact=artifact)
    except (TypeError, ValueError) as exc:
        raise ValuationRunContextError("price-blind artifact does not replay") from exc
    if (
        payload["price_blind_input_fingerprint"] != artifact.fingerprint
        or payload["expected_freeze_fingerprint"] != freeze_result.fingerprint
    ):
        raise ValuationRunContextError("valuation run input changed the price-blind freeze")
    proposal = _security_proposal(payload["security_proposal"])
    security = compile_security_identity(
        graph=graph,
        expected_freeze=freeze_result,
        proposal=proposal,
    )
    if payload["expected_security_fingerprint"] != security.fingerprint:
        raise ValuationRunContextError("valuation run input changed security authority")
    try:
        proposals = tuple(_assumption_proposal(item) for item in payload["assumption_proposals"])
        reviews = tuple(AssumptionReviewRequest(**item) for item in payload["assumption_reviews"])
        market_clock = RunClock(**payload["clock"]["market"])
        execution_clock = OwnerValuationExecutionClock(**payload["clock"]["execution"])
        clock = ValuationRunClock(market_clock, execution_clock)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValuationRunContextError("valuation run inputs or clocks do not replay") from exc
    bundle_contents: dict[str, bytes] = {}
    artifacts = payload["research_bundle_artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "research-bundle.json",
        "run-manifest.json",
    }:
        raise ValuationRunContextError("research Bundle artifact set is not closed")
    for name, record in artifacts.items():
        if not isinstance(record, dict) or set(record) != {"payload", "sha256"}:
            raise ValuationRunContextError("research Bundle artifact record is invalid")
        raw = _canonical_file(record["payload"])
        if record["sha256"] != _sha256(raw):
            raise ValuationRunContextError("research Bundle artifact hash does not replay")
        bundle_contents[name] = raw
    _validate_research_bundle_payload(graph, artifacts)
    return ValuationRunInputContext(
        graph=graph,
        expected_freeze=freeze_result,
        expected_security=security,
        assumption_proposals=proposals,
        assumption_reviews=reviews,
        clock=clock,
        research_bundle_contents=freeze(bundle_contents),
        context_fingerprint=supplied_fingerprint,
    )


__all__ = (
    "CORE_JSON_MAX_BYTES",
    "RESEARCH_INPUT_FILE_MAX_BYTES",
    "RESEARCH_INPUT_TOTAL_MAX_BYTES",
    "VALUATION_RUN_INPUT_FILENAME",
    "ValuationRunContextError",
    "ValuationRunInputContext",
    "load_valuation_run_input_context",
    "write_valuation_run_input_context",
)
