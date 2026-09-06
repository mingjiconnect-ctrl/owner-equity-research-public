"""Retained-authority contracts for downstream valuation synthesis.

The public dictionaries emitted by these objects are publication projections only. A
live object additionally retains the exact typed authorities from which that projection
was derived. Consequently a projection cannot be deserialized into a trusted live
object and coordinated ``dataclasses.replace`` attacks are replayed in ``__post_init__``.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from functools import cache, wraps
from pathlib import Path
from threading import get_ident
from types import MappingProxyType, MemberDescriptorType
from typing import Any, ClassVar, ParamSpec, TypeVar

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .contracts import Contract, ResearchBundle
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .research_bundle_validation import (
    dependency_closure,
    validate_research_bundle,
)
from .validation import ContractGraph

EXTENSION_SCHEMA_NAMES = (
    "named-human-review-authority",
    "reviewed-peer-set-authority",
    "valuation-basis-receipt",
    "forward-reoi-input-receipt",
    "forward-reoi-valuation-result",
    "comparable-input-receipt",
    "comparable-valuation-result",
    "composite-valuation-result",
    "score-v2",
    "owner-scorecard",
)
EXTENSION_SCHEMA_MAX_BYTES = 16 * 1024 * 1024
EXTENSION_SCHEMA_TOTAL_MAX_BYTES = 64 * 1024 * 1024
EXTENSION_DECIMAL_DOMAIN_LIMIT = 1000


def extension_decimal_in_domain(value: Decimal) -> bool:
    """Return whether a finite Decimal fits the shared extension arithmetic domain."""

    exponent = value.as_tuple().exponent
    return (
        value.is_finite()
        and isinstance(exponent, int)
        and exponent >= -EXTENSION_DECIMAL_DOMAIN_LIMIT
        and abs(value.adjusted()) <= EXTENSION_DECIMAL_DOMAIN_LIMIT
    )

_REVIEW_SCOPES = frozenset(
    {
        "valuation_basis",
        "forward_reoi",
        "peer_set_selection",
        "comparable_forecast",
        "futu_optional_data_plan",
        "score:graham",
        "score:buffett",
        "score:munger",
        "score:duan_yongping",
    }
)
_EVIDENCE_FIELDS = frozenset({"object_type", "object_id", "fingerprint"})
_GRAPH_ID_ATTRIBUTES = {
    "documents": "document_id",
    "facts": "fact_id",
    "claims": "claim_id",
    "assumptions": "assumption_id",
    "calculations": "calculation_id",
    "periods": "period_id",
    "reconciliations": "reconciliation_id",
    "quarterly_updates": "update_id",
    "filing_artifacts": "artifact_id",
    "extraction_candidates": "candidate_id",
    "evidence_promotions": "promotion_id",
    "segment_definitions": "segment_id",
    "segment_snapshots": "snapshot_id",
    "footnote_reviews": "review_id",
    "accounting_quality_findings": "finding_id",
    "accounting_quality_reviews": "review_id",
    "context_observations": "observation_id",
    "competitive_context_snapshots": "context_snapshot_id",
    "analytical_claim_candidates": "candidate_id",
    "analytical_claim_review_decisions": "decision_id",
    "business_model_snapshots": "snapshot_id",
    "competitive_advantage_hypotheses": "hypothesis_id",
    "business_quality_reviews": "review_id",
    "management_statements": "statement_id",
    "management_statement_candidates": "candidate_id",
    "management_statement_review_decisions": "decision_id",
    "management_commitments": "commitment_id",
    "management_outcomes": "outcome_id",
    "capital_allocation_event_candidates": "candidate_id",
    "capital_allocation_event_review_decisions": "decision_id",
    "capital_allocation_events": "event_id",
    "capital_allocation_outcomes": "outcome_id",
    "source_search_receipts": "receipt_id",
    "management_reviews": "review_id",
    "capital_allocation_reviews": "review_id",
    "scores": "score_id",
    "manifests": "run_id",
}


class ExtensionAuthorityError(ValueError):
    """A retained synthesis/scoring authority does not replay."""


@dataclass(frozen=True, slots=True)
class _ExactAuthorityWitness:
    references: tuple[object, ...]
    exact_types: tuple[type[object], ...]
    typed_fingerprints: tuple[str, ...]
    authority_identity_required: tuple[bool, ...]

    def matches(self, other: _ExactAuthorityWitness) -> bool:
        return (
            len(self.references) == len(other.references)
            and all(
                retained is observed
                for retained, observed in zip(
                    self.references,
                    other.references,
                    strict=True,
                )
            )
            and self.exact_types == other.exact_types
            and self.typed_fingerprints == other.typed_fingerprints
            and self.authority_identity_required
            == other.authority_identity_required
        )

    def stable_after_replay(self, other: _ExactAuthorityWitness) -> bool:
        return (
            len(self.references) == len(other.references)
            and self.exact_types == other.exact_types
            and self.typed_fingerprints == other.typed_fingerprints
            and self.authority_identity_required
            == other.authority_identity_required
            and all(
                not required or retained is observed
                for retained, observed, required in zip(
                    self.references,
                    other.references,
                    self.authority_identity_required,
                    strict=True,
                )
            )
        )


@dataclass(frozen=True, slots=True)
class _ExtensionReplayCacheEntry:
    authority: object
    public_sha256: str
    public_typed_sha256: str
    private_witness: _ExactAuthorityWitness


@dataclass(frozen=True, slots=True)
class _CompletedRunReplayCacheEntry:
    run_result: object
    binding_witness: _ExactAuthorityWitness
    archive: object
    request_bytes: bytes
    result_bytes: bytes


def _current_task_id() -> int | None:
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return None
    return id(task) if task is not None else None


@dataclass(slots=True)
class _RetainedReplaySession:
    extensions: dict[int, _ExtensionReplayCacheEntry] = field(default_factory=dict)
    completed_runs: dict[int, _CompletedRunReplayCacheEntry] = field(default_factory=dict)
    visiting: set[tuple[str, int]] = field(default_factory=set)
    active: bool = True
    owner_thread_id: int = field(default_factory=get_ident)
    owner_task_id: int | None = field(default_factory=_current_task_id)


_RETAINED_REPLAY_SESSION: ContextVar[_RetainedReplaySession | None] = ContextVar(
    "owner_research_retained_replay_session",
    default=None,
)
_P = ParamSpec("_P")
_R = TypeVar("_R")


@contextmanager
def retained_authority_replay_session() -> Iterator[None]:
    """Share replay work only inside one synchronous top-level operation."""

    current = _RETAINED_REPLAY_SESSION.get()
    if (
        current is not None
        and current.active
        and current.owner_thread_id == get_ident()
        and current.owner_task_id == _current_task_id()
    ):
        yield
        return
    session = _RetainedReplaySession()
    token = _RETAINED_REPLAY_SESSION.set(session)
    try:
        yield
    finally:
        session.active = False
        session.extensions.clear()
        session.completed_runs.clear()
        session.visiting.clear()
        _RETAINED_REPLAY_SESSION.reset(token)


def retained_authority_replay_scope(
    function: Callable[_P, _R],
) -> Callable[_P, _R]:
    """Decorate a synchronous public operation with one retained replay session."""

    @wraps(function)
    def scoped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with retained_authority_replay_session():
            return function(*args, **kwargs)

    return scoped


def _component_lock_path_live_payload(value: Path) -> dict[str, str]:
    from .component_lock import file_sha256

    absolute = Path(value).expanduser().absolute()
    try:
        digest = file_sha256(absolute)
    except (OSError, TypeError, ValueError) as exc:
        raise ExtensionAuthorityError(
            "retained ContractGraph component lock is unavailable"
        ) from exc
    return {
        "path": str(absolute),
        "file_sha256": digest,
    }


def _validate_frozen_map_storage(value: FrozenMap) -> None:
    items = value._items
    index = value._index
    index_items = (
        tuple(sorted(index.items()))
        if type(index) is MappingProxyType
        else ()
    )
    if (
        type(items) is not tuple
        or type(index) is not MappingProxyType
        or any(type(key) is not str for key in index)
        or items != index_items
        or any(
            item_key is not index_key or item_value is not index_value
            for (item_key, item_value), (index_key, index_value) in zip(
                items,
                index_items,
                strict=True,
            )
        )
    ):
        raise ExtensionAuthorityError("retained FrozenMap storage does not replay")


def _live_json_value(value: object, *, visiting: set[int]) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return {"bytes_sha256": hashlib.sha256(bytes(value)).hexdigest()}
    if isinstance(value, (date, datetime)):
        return {"iso8601": value.isoformat()}
    if type(value) is FrozenMap:
        _validate_frozen_map_storage(value)
    tracked = is_dataclass(value) or isinstance(value, (Mapping, Sequence, set, frozenset))
    identity = id(value)
    if tracked:
        if identity in visiting:
            raise ExtensionAuthorityError("retained-authority live digest cycle detected")
        visiting.add(identity)
    try:
        if isinstance(value, Mapping):
            entries = [
                (
                    {
                        "exact_type": (
                            f"{type(key).__module__}.{type(key).__qualname__}"
                        ),
                        "value": _live_json_value(key, visiting=visiting),
                    },
                    _live_json_value(item, visiting=visiting),
                )
                for key, item in value.items()
            ]
            return {
                "exact_type": f"{type(value).__module__}.{type(value).__qualname__}",
                "mapping_entries": tuple(
                    sorted(entries, key=lambda pair: canonical_json(pair[0]))
                )
            }
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return {
                "exact_type": f"{type(value).__module__}.{type(value).__qualname__}",
                "sequence_items": tuple(
                    _live_json_value(item, visiting=visiting) for item in value
                ),
            }
        if isinstance(value, (set, frozenset)):
            normalized = tuple(_live_json_value(item, visiting=visiting) for item in value)
            return {
                "exact_type": f"{type(value).__module__}.{type(value).__qualname__}",
                "set_items": tuple(sorted(normalized, key=canonical_json)),
            }
        if is_dataclass(value):
            return {
                "exact_type": f"{type(value).__module__}.{type(value).__qualname__}",
                "dataclass_fields": {
                    item.name: _live_json_value(
                        getattr(value, item.name),
                        visiting=visiting,
                    )
                    for item in fields(value)
                },
            }
        return {
            "opaque_type": f"{type(value).__module__}.{type(value).__qualname__}"
        }
    finally:
        if tracked:
            visiting.remove(identity)


def _extension_public_live_sha256(value: ExtensionContract) -> str:
    return canonical_sha256(
        tuple(
            (
                item.name,
                f"{type(field_value).__module__}.{type(field_value).__qualname__}",
                _live_json_value(field_value, visiting=set()),
            )
            for item in fields(value)
            if item.metadata.get("serialize", True)
            for field_value in (getattr(value, item.name),)
        )
    )


def _witness_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _is_completed_run_result(value: object) -> bool:
    return (
        type(value).__module__ == "owner_research.valuation_run"
        and type(value).__qualname__ == "ValuationRunResult"
    )


def _is_contract_graph(value: object) -> bool:
    return (
        type(value).__module__ == "owner_research.validation"
        and type(value).__qualname__ == "ContractGraph"
    )


def _authority_witness(values: Sequence[object]) -> _ExactAuthorityWitness:
    references: list[object] = []
    exact_types: list[type[object]] = []
    typed_fingerprints: list[str] = []
    authority_identity_required: list[bool] = []
    visiting: set[int] = set()
    memo: dict[tuple[int, bool], str] = {}

    def typed_live_sort_key(value: object) -> str:
        return canonical_json(
            {
                "exact_type": f"{type(value).__module__}.{type(value).__qualname__}",
                "value": _live_json_value(value, visiting=set()),
            }
        )

    def capture_object_state(value: object) -> tuple[object, ...]:
        state: list[object] = []
        attributes = getattr(value, "__dict__", None)
        if isinstance(attributes, Mapping):
            state.append(
                (
                    "__dict__",
                    tuple(
                        (capture(key), capture(item))
                        for key, item in sorted(
                            attributes.items(),
                            key=lambda pair: (
                                typed_live_sort_key(pair[0]),
                                id(pair[0]),
                            ),
                        )
                    ),
                )
            )
        for owner in type(value).__mro__:
            slots = getattr(owner, "__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            for declared_name in slots:
                if declared_name in {"__dict__", "__weakref__"}:
                    continue
                storage_name = declared_name
                if declared_name.startswith("__") and not declared_name.endswith("__"):
                    owner_name = owner.__name__.lstrip("_")
                    if owner_name:
                        storage_name = f"_{owner_name}{declared_name}"
                descriptor = vars(owner).get(storage_name)
                if type(descriptor) is not MemberDescriptorType:
                    continue
                try:
                    slot_value = descriptor.__get__(value, type(value))
                except AttributeError:
                    continue
                state.append(
                    (
                        "__slot__",
                        f"{owner.__module__}.{owner.__qualname__}",
                        declared_name,
                        capture(slot_value),
                    )
                )
        return tuple(state)

    def capture(value: object, *, component_lock_path: bool = False) -> str:
        identity = id(value)
        canonical_value = type(value) in {
            type(None),
            bool,
            int,
            float,
            str,
            bytes,
            bytearray,
            date,
            datetime,
            dict,
            list,
            tuple,
            set,
            frozenset,
            FrozenMap,
            MappingProxyType,
        } or isinstance(value, Path)
        if type(value) is FrozenMap:
            _validate_frozen_map_storage(value)
        identity_required = not canonical_value
        tracked = (
            isinstance(value, (Mapping, Sequence, set, frozenset))
            or is_dataclass(value)
            or hasattr(value, "__dict__")
            or hasattr(type(value), "__slots__")
            or component_lock_path
        ) and not isinstance(value, (str, bytes, bytearray, Path))
        if component_lock_path and isinstance(value, Path):
            tracked = True
        if tracked and identity in visiting:
            raise ExtensionAuthorityError("retained-authority live witness cycle detected")
        references.append(value)
        exact_types.append(type(value))
        authority_identity_required.append(identity_required)
        position = len(typed_fingerprints)
        typed_fingerprints.append("")
        memo_key = (identity, component_lock_path)
        cached_digest = memo.get(memo_key) if identity_required else None
        if cached_digest is not None:
            typed_fingerprints[position] = cached_digest
            return cached_digest
        if tracked:
            visiting.add(identity)
        type_name = f"{type(value).__module__}.{type(value).__qualname__}"
        try:
            if _is_completed_run_result(value):
                completed = _completed_run_witness(value)
                for reference, exact_type, fingerprint in zip(
                    completed.references[1:],
                    completed.exact_types[1:],
                    completed.typed_fingerprints[1:],
                    strict=True,
                ):
                    references.append(reference)
                    exact_types.append(exact_type)
                    typed_fingerprints.append(fingerprint)
                authority_identity_required.extend(
                    completed.authority_identity_required[1:]
                )
                payload: object = {
                    "completed_run_binding": completed.typed_fingerprints[0]
                }
            elif isinstance(value, ExtensionContract):
                public_fields = tuple(
                    item
                    for item in fields(value)
                    if item.metadata.get("serialize", True)
                )
                private_fields = tuple(
                    item
                    for item in fields(value)
                    if not item.metadata.get("serialize", True)
                )
                payload = {
                    "public_live": tuple(
                        (item.name, capture(getattr(value, item.name)))
                        for item in public_fields
                    ),
                    "private": tuple(
                        (item.name, capture(getattr(value, item.name)))
                        for item in private_fields
                    ),
                }
            elif isinstance(value, Mapping):
                payload = {
                    "items": tuple(
                        (capture(key), capture(item))
                        for key, item in sorted(
                            value.items(),
                            key=lambda pair: (
                                typed_live_sort_key(pair[0]),
                                id(pair[0]),
                            ),
                        )
                    ),
                    "authority_state": (
                        capture_object_state(value)
                        if identity_required
                        else None
                    ),
                }
            elif isinstance(value, Sequence) and not isinstance(
                value,
                (str, bytes, bytearray),
            ):
                payload = {
                    "items": tuple(capture(item) for item in value),
                    "authority_state": (
                        capture_object_state(value)
                        if identity_required
                        else None
                    ),
                }
            elif isinstance(value, (set, frozenset)):
                payload = {
                    "items": tuple(
                        capture(item)
                        for item in sorted(
                            value,
                            key=lambda item: (typed_live_sort_key(item), id(item)),
                        )
                    ),
                    "authority_state": (
                        capture_object_state(value)
                        if identity_required
                        else None
                    ),
                }
            elif is_dataclass(value):
                payload = tuple(
                    (
                        item.name,
                        capture(
                            getattr(value, item.name),
                            component_lock_path=(
                                _is_contract_graph(value)
                                and item.name == "component_lock_path"
                            ),
                        ),
                    )
                    for item in fields(value)
                )
            elif isinstance(value, Path):
                payload = (
                    _component_lock_path_live_payload(value)
                    if component_lock_path
                    else str(value)
                )
            elif type(value) in {date, datetime}:
                payload = value.isoformat()
            elif isinstance(value, (bytes, bytearray)):
                payload = hashlib.sha256(bytes(value)).hexdigest()
            elif value is None or isinstance(value, (bool, int, float, str)):
                payload = value
            else:
                payload = capture_object_state(value)
            digest = _witness_sha256({"exact_type": type_name, "live": payload})
            typed_fingerprints[position] = digest
            if identity_required:
                memo[memo_key] = digest
            return digest
        finally:
            if tracked:
                visiting.remove(identity)

    for value in values:
        capture(value)
    return _ExactAuthorityWitness(
        references=tuple(references),
        exact_types=tuple(exact_types),
        typed_fingerprints=tuple(typed_fingerprints),
        authority_identity_required=tuple(authority_identity_required),
    )


def _completed_run_witness(run_result: object) -> _ExactAuthorityWitness:
    from .valuation_run import (
        _archive_integrity_binding,
        _execution_integrity_binding,
        _preparation_integrity_binding,
    )

    try:
        receipt = run_result.input_receipt  # type: ignore[attr-defined]
        preparation = run_result.preparation  # type: ignore[attr-defined]
        execution = run_result.execution  # type: ignore[attr-defined]
        archive = run_result.archive  # type: ignore[attr-defined]
        final_request = execution.final_request_result
        request_receipt = execution.final_request_receipt
        kernel_receipt = execution.kernel_execution_receipt
        execution_handoffs = execution.execution_handoffs
        result_bytes = execution.result_bytes
        child_witness = _authority_witness(
            (receipt, preparation, execution, archive)
        )
        binding_projection = {
            "run_fingerprint": run_result.fingerprint,
            "run_status": run_result.status,
            "run_issuer_id": run_result.issuer_id,
            "run_data_cutoff_date": run_result.data_cutoff_date,
            "run_issue_codes": run_result.issue_codes,
            "input_receipt_id": receipt.receipt_id,
            "input_component_lock_sha256": receipt.component_lock_sha256,
            "preparation_binding": _preparation_integrity_binding(preparation),
            "execution_binding": _execution_integrity_binding(execution),
            "archive_binding": _archive_integrity_binding(archive),
            "execution_status": execution.status,
            "execution_preparation_fingerprint": execution.preparation_fingerprint,
            "execution_expected_freeze_fingerprint": (
                execution.expected_freeze_fingerprint
            ),
            "final_request_sha256": final_request.request_sha256,
            "final_request_receipt_fingerprint": request_receipt.fingerprint,
            "kernel_execution_receipt_fingerprint": kernel_receipt.fingerprint,
            "execution_handoff_fingerprints": tuple(
                item.fingerprint for item in execution_handoffs
            ),
            "execution_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "archive_fingerprint": archive.fingerprint,
            "archive_file_sha256": to_json_value(archive.file_sha256),
            "archive_request_sha256": archive.manifest["valuation_request_sha256"],
            "archive_result_sha256": archive.manifest["valuation_result_sha256"],
            "child_root_live_sha256": canonical_sha256(
                child_witness.typed_fingerprints
            ),
        }
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ExtensionAuthorityError(
            "completed valuation run lacks one exact typed binding"
        ) from exc
    binding_fingerprint = canonical_sha256(binding_projection)
    return _ExactAuthorityWitness(
        references=(run_result, *child_witness.references),
        exact_types=(type(run_result), *child_witness.exact_types),
        typed_fingerprints=(binding_fingerprint, *child_witness.typed_fingerprints),
        authority_identity_required=(
            True,
            *child_witness.authority_identity_required,
        ),
    )


def replay_retained_completed_run_once(
    run_result: object,
    replay: Callable[[object], tuple[object, dict[str, Any], dict[str, Any]]],
) -> tuple[object, dict[str, Any], dict[str, Any]]:
    """Replay one completed run once per session and rematerialize cached JSON bytes."""

    with retained_authority_replay_session():
        session = _RETAINED_REPLAY_SESSION.get()
        assert session is not None
        key = ("completed_run", id(run_result))
        if key in session.visiting:
            raise ExtensionAuthorityError("retained-authority replay cycle detected")
        witness = _completed_run_witness(run_result)
        cached = session.completed_runs.get(id(run_result))
        if cached is not None:
            if (
                cached.run_result is run_result
                and cached.binding_witness.stable_after_replay(witness)
            ):
                return (
                    cached.archive,
                    json.loads(cached.request_bytes),
                    json.loads(cached.result_bytes),
                )
            raise ExtensionAuthorityError(
                "cached completed valuation run authority changed"
            )
        session.visiting.add(key)
        try:
            archive, request, result = replay(run_result)
            request_bytes = canonical_json(request).encode("utf-8")
            result_bytes = canonical_json(result).encode("utf-8")
            after = _completed_run_witness(run_result)
            if not witness.stable_after_replay(after):
                raise ExtensionAuthorityError(
                    "completed valuation run changed during retained replay"
                )
            session.completed_runs[id(run_result)] = _CompletedRunReplayCacheEntry(
                run_result=run_result,
                binding_witness=after,
                archive=archive,
                request_bytes=request_bytes,
                result_bytes=result_bytes,
            )
            return archive, request, result
        finally:
            session.visiting.remove(key)


def extension_schema_directory() -> Path:
    packaged = Path(__file__).parent / "extension_schemas"
    repository = Path(__file__).parents[2] / "extension_schemas"
    for candidate in (packaged, repository):
        try:
            details = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(details.st_mode):
            return candidate
    raise FileNotFoundError("valuation extension schema directory is unavailable")


def _read_extension_schema(path: Path, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExtensionAuthorityError(f"extension Schema {name} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > EXTENSION_SCHEMA_MAX_BYTES
        ):
            raise ExtensionAuthorityError(
                f"extension Schema {name} is not one bounded regular file"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, EXTENSION_SCHEMA_MAX_BYTES - consumed + 1),
            )
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > EXTENSION_SCHEMA_MAX_BYTES:
                raise ExtensionAuthorityError(f"extension Schema {name} exceeds the byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or consumed != before.st_size:
            raise ExtensionAuthorityError(f"extension Schema {name} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _unique_schema_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ExtensionAuthorityError(f"extension Schema repeats key {key!r}")
        output[key] = value
    return output


def _reject_schema_constant(token: str) -> None:
    raise ExtensionAuthorityError(f"extension Schema contains non-finite value {token}")


def _parse_extension_schema(raw: bytes, name: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_schema_object,
            parse_constant=_reject_schema_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExtensionAuthorityError(f"extension Schema {name} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ExtensionAuthorityError(f"extension Schema {name} must be a JSON object")
    # Normalize the trusted source resource once before it enters the registry. The
    # checked source bytes remain human-readable, while every consumer sees one
    # deterministic JSON value with non-finite numbers excluded.
    return json.loads(
        canonical_json(payload),
        object_pairs_hook=_unique_schema_object,
        parse_constant=_reject_schema_constant,
    )


@cache
def _extension_schema_set() -> dict[str, dict[str, Any]]:
    directory = extension_schema_directory()
    schemas: dict[str, dict[str, Any]] = {}
    consumed = 0
    for name in EXTENSION_SCHEMA_NAMES:
        raw = _read_extension_schema(directory / f"{name}.schema.json", name)
        consumed += len(raw)
        if consumed > EXTENSION_SCHEMA_TOTAL_MAX_BYTES:
            raise ExtensionAuthorityError("extension Schema set exceeds the cumulative byte limit")
        schemas[name] = _parse_extension_schema(raw, name)
    return schemas


def load_extension_schema(name: str) -> dict[str, Any]:
    if name not in EXTENSION_SCHEMA_NAMES:
        raise KeyError(f"unknown valuation extension schema: {name}")
    return copy.deepcopy(_extension_schema_set()[name])


@cache
def _extension_registry() -> Registry:
    return Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema))
        for schema in (load_extension_schema(name) for name in EXTENSION_SCHEMA_NAMES)
    )


@cache
def _extension_validator(name: str) -> Draft202012Validator:
    schema = load_extension_schema(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
        registry=_extension_registry(),
    )


def validate_extension_payload(name: str, payload: dict[str, Any]) -> None:
    _extension_validator(name).validate(payload)


def _timestamp(value: object, label: str) -> str:
    if type(value) is not str:
        raise ExtensionAuthorityError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExtensionAuthorityError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ExtensionAuthorityError(f"{label} must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _graph_object_id(graph_field: str, item: object) -> str:
    attribute = _GRAPH_ID_ATTRIBUTES.get(graph_field)
    value = getattr(item, attribute, None) if attribute is not None else None
    if type(value) is not str or not value:
        raise ExtensionAuthorityError(
            f"{type(item).__name__} has no exact {graph_field} identifier"
        )
    return value


def _object_fingerprint(item: Contract) -> str:
    fingerprint = getattr(item, "fingerprint", None)
    if type(fingerprint) is str and len(fingerprint) == 64:
        return fingerprint
    return canonical_sha256(item.to_dict())


def _graph_fingerprint(graph: ContractGraph) -> str:
    graph.validate()
    projection: dict[str, list[str]] = {}
    for graph_field in fields(graph):
        if graph_field.name == "component_lock_path":
            continue
        projection[graph_field.name] = [
            _object_fingerprint(item) for item in getattr(graph, graph_field.name)
        ]
    return canonical_sha256(projection)


def _bundle_roots(bundle: ResearchBundle) -> tuple[str, ...]:
    roots: list[str] = []
    for reference in bundle.module_references:
        object_ids = reference["object_ids"]
        if not isinstance(object_ids, Sequence) or isinstance(object_ids, (str, bytes)):
            raise ExtensionAuthorityError("ResearchBundle module object IDs are invalid")
        roots.extend(object_ids)
    return tuple(roots)


def _normalized_binding(
    value: object,
    *,
    registry: Mapping[str, tuple[str, Contract]],
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _EVIDENCE_FIELDS:
        raise ExtensionAuthorityError("review evidence binding fields are not closed")
    object_type = value["object_type"]
    object_id = value["object_id"]
    fingerprint = value["fingerprint"]
    if any(type(item) is not str or not item for item in (object_type, object_id, fingerprint)):
        raise ExtensionAuthorityError("review evidence binding identity is invalid")
    resolved = registry.get(object_id)
    if resolved is None:
        raise ExtensionAuthorityError("review evidence binding is outside the ResearchBundle")
    resolved_type, contract = resolved
    if object_type != resolved_type or fingerprint != _object_fingerprint(contract):
        raise ExtensionAuthorityError("review evidence binding does not replay")
    return {
        "object_type": object_type,
        "object_id": object_id,
        "fingerprint": fingerprint,
    }


@dataclass(frozen=True, slots=True)
class NamedHumanReviewAuthority:
    """Exact ContractGraph/ResearchBundle-backed human review decision."""

    schema_version: str
    review_id: str
    scope: str
    issuer_id: str
    data_cutoff_date: str
    reviewer_id: str
    reviewed_at: str
    rationale: str
    graph: ContractGraph = field(repr=False)
    research_bundle: ResearchBundle = field(repr=False)
    reviewed_payload: FrozenMap
    evidence_bindings: tuple[FrozenMap, ...]
    review_fingerprint: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != "1.0.0"
            or self.scope not in _REVIEW_SCOPES
            or type(self.graph) is not ContractGraph
            or type(self.research_bundle) is not ResearchBundle
        ):
            raise ExtensionAuthorityError("named-human review authority type is invalid")
        try:
            self.graph.validate()
            if self.research_bundle not in self.graph.research_bundles:
                raise ExtensionAuthorityError(
                    "named-human review does not retain a graph ResearchBundle"
                )
            validate_research_bundle(self.graph, self.research_bundle)
        except (OSError, ValueError) as exc:
            if isinstance(exc, ExtensionAuthorityError):
                raise
            raise ExtensionAuthorityError("named-human review graph does not replay") from exc
        if (
            self.issuer_id != self.research_bundle.issuer_id
            or self.data_cutoff_date != self.research_bundle.data_cutoff_date
        ):
            raise ExtensionAuthorityError("named-human review identity changed")
        try:
            cutoff = date.fromisoformat(self.data_cutoff_date)
        except (TypeError, ValueError) as exc:
            raise ExtensionAuthorityError("named-human review cutoff is invalid") from exc
        if (
            type(self.reviewer_id) is not str
            or not self.reviewer_id.startswith("human:")
            or not self.reviewer_id[6:].strip()
            or type(self.rationale) is not str
            or not self.rationale.strip()
        ):
            raise ExtensionAuthorityError(
                "named-human review requires a named reviewer and rationale"
            )
        normalized_time = _timestamp(self.reviewed_at, "reviewed_at")
        if datetime.fromisoformat(normalized_time.replace("Z", "+00:00")).date() < cutoff:
            raise ExtensionAuthorityError("named-human review predates its evidence cutoff")
        if not isinstance(self.reviewed_payload, Mapping):
            raise ExtensionAuthorityError("named-human reviewed payload must be an object")
        frozen_payload = freeze(to_json_value(self.reviewed_payload))
        closure = dependency_closure(self.graph, _bundle_roots(self.research_bundle))
        if not isinstance(self.evidence_bindings, Sequence) or isinstance(
            self.evidence_bindings, (str, bytes)
        ):
            raise ExtensionAuthorityError("named-human review bindings must be a sequence")
        bindings = tuple(
            _normalized_binding(item, registry=closure) for item in self.evidence_bindings
        )
        if not bindings:
            raise ExtensionAuthorityError("named-human review requires bound evidence")
        identities = {
            (item["object_type"], item["object_id"], item["fingerprint"])
            for item in bindings
        }
        if len(identities) != len(bindings):
            raise ExtensionAuthorityError("named-human review evidence is duplicated")
        frozen_bindings = tuple(
            freeze(item)
            for item in sorted(
                bindings,
                key=lambda item: (
                    item["object_type"],
                    item["object_id"],
                    item["fingerprint"],
                ),
            )
        )
        if (
            self.reviewed_at != normalized_time
            or to_json_value(self.reviewed_payload) != to_json_value(frozen_payload)
            or to_json_value(self.evidence_bindings) != to_json_value(frozen_bindings)
        ):
            raise ExtensionAuthorityError(
                "named-human review projection is not canonical"
            )
        object.__setattr__(self, "reviewed_at", normalized_time)
        object.__setattr__(self, "reviewed_payload", frozen_payload)
        object.__setattr__(self, "evidence_bindings", frozen_bindings)
        values = self._manifest_values()
        expected_fingerprint = canonical_sha256(values)
        expected_id = (
            f"named-human-review:{self.scope}:{self.issuer_id}:"
            f"{expected_fingerprint[:24]}"
        )
        if self.review_id != expected_id or self.review_fingerprint != expected_fingerprint:
            raise ExtensionAuthorityError("named-human review identity is not deterministic")
        validate_extension_payload("named-human-review-authority", self.to_dict())

    def _manifest_values(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scope": self.scope,
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "reviewer_id": self.reviewer_id,
            "reviewed_at": self.reviewed_at,
            "rationale": self.rationale,
            "graph_fingerprint": _graph_fingerprint(self.graph),
            "research_bundle_id": self.research_bundle.bundle_id,
            "research_bundle_fingerprint": self.research_bundle.fingerprint,
            "reviewed_payload": to_json_value(self.reviewed_payload),
            "evidence_bindings": to_json_value(self.evidence_bindings),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._manifest_values(),
            "review_id": self.review_id,
            "review_fingerprint": self.review_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return self.review_fingerprint


def build_named_human_review_authority(
    *,
    scope: str,
    graph: ContractGraph,
    research_bundle: ResearchBundle,
    reviewer_id: str,
    reviewed_at: str,
    rationale: str,
    reviewed_payload: Mapping[str, Any],
    evidence_bindings: Sequence[Mapping[str, str]],
) -> NamedHumanReviewAuthority:
    normalized_time = _timestamp(reviewed_at, "reviewed_at")
    normalized_bindings = sorted(
        (dict(item) for item in evidence_bindings),
        key=lambda item: (
            item.get("object_type", ""),
            item.get("object_id", ""),
            item.get("fingerprint", ""),
        ),
    )
    provisional = {
        "schema_version": "1.0.0",
        "scope": scope,
        "issuer_id": research_bundle.issuer_id,
        "data_cutoff_date": research_bundle.data_cutoff_date,
        "reviewer_id": reviewer_id,
        "reviewed_at": normalized_time,
        "rationale": rationale,
        "graph_fingerprint": _graph_fingerprint(graph),
        "research_bundle_id": research_bundle.bundle_id,
        "research_bundle_fingerprint": research_bundle.fingerprint,
        "reviewed_payload": to_json_value(reviewed_payload),
        "evidence_bindings": normalized_bindings,
    }
    fingerprint = canonical_sha256(provisional)
    return NamedHumanReviewAuthority(
        schema_version="1.0.0",
        review_id=f"named-human-review:{scope}:{research_bundle.issuer_id}:{fingerprint[:24]}",
        scope=scope,
        issuer_id=research_bundle.issuer_id,
        data_cutoff_date=research_bundle.data_cutoff_date,
        reviewer_id=reviewer_id,
        reviewed_at=normalized_time,
        rationale=rationale,
        graph=graph,
        research_bundle=research_bundle,
        reviewed_payload=freeze(reviewed_payload),
        evidence_bindings=tuple(freeze(item) for item in normalized_bindings),
        review_fingerprint=fingerprint,
    )


def _serialized_fields(instance: object) -> tuple[Any, ...]:
    return tuple(item for item in fields(instance) if item.metadata.get("serialize", True))


def _serialized_value(value: object) -> Any:
    if isinstance(value, ExtensionContract):
        return value.to_dict()
    return to_json_value(value)


def _replay_retained_extension_authority(
    contract: ExtensionContract,
    replay: Callable[[ExtensionContract], None],
) -> None:
    session = _RETAINED_REPLAY_SESSION.get()
    if session is None:
        raise ExtensionAuthorityError("retained replay session is unavailable")
    key = ("extension", id(contract))
    if key in session.visiting:
        raise ExtensionAuthorityError("retained-authority replay cycle detected")
    public_projection = contract.to_dict()
    public_sha256 = canonical_sha256(public_projection)
    public_typed_sha256 = _extension_public_live_sha256(contract)
    private_names = tuple(
        item.name
        for item in fields(contract)
        if not item.metadata.get("serialize", True)
    )
    private_values = tuple(getattr(contract, name) for name in private_names)
    private_witness = _authority_witness(private_values)
    cached = session.extensions.get(id(contract))
    if cached is not None:
        if (
            cached.authority is contract
            and cached.public_sha256 == public_sha256
            and cached.public_typed_sha256 == public_typed_sha256
            and cached.private_witness.stable_after_replay(private_witness)
        ):
            return
        raise ExtensionAuthorityError(
            "cached retained extension authority changed"
        )
    session.visiting.add(key)
    try:
        replay(contract)
        after_public_projection = contract.to_dict()
        after_public_sha256 = canonical_sha256(after_public_projection)
        after_public_typed_sha256 = _extension_public_live_sha256(contract)
        after_private_witness = _authority_witness(
            tuple(getattr(contract, name) for name in private_names)
        )
        if (
            after_public_sha256 != public_sha256
            or after_public_typed_sha256 != public_typed_sha256
            or not private_witness.stable_after_replay(after_private_witness)
        ):
            raise ExtensionAuthorityError(
                "retained extension authority changed during replay"
            )
        session.extensions[id(contract)] = _ExtensionReplayCacheEntry(
            authority=contract,
            public_sha256=after_public_sha256,
            public_typed_sha256=after_public_typed_sha256,
            private_witness=after_private_witness,
        )
    finally:
        session.visiting.remove(key)


@dataclass(frozen=True, slots=True)
class ExtensionContract:
    """Frozen projection plus exact private authorities replayed on construction."""

    SCHEMA_NAME: ClassVar[str]

    def __post_init__(self) -> None:
        with retained_authority_replay_session():
            payload = {
                item.name: _serialized_value(getattr(self, item.name))
                for item in _serialized_fields(self)
            }
            validate_extension_payload(self.SCHEMA_NAME, payload)
            for item in _serialized_fields(self):
                object.__setattr__(self, item.name, freeze(getattr(self, item.name)))
            identity_fields = tuple(
                name
                for name in ("receipt_id", "result_id", "score_id", "scorecard_id")
                if name in payload
            )
            if len(identity_fields) != 1:
                raise ValueError("extension contract requires one deterministic object ID")
            identity_field = identity_fields[0]
            supplied_id = payload.pop(identity_field)
            if type(supplied_id) is not str or not supplied_id.endswith(
                f":{canonical_sha256(payload)[:24]}"
            ):
                raise ValueError("extension contract object ID is not deterministic")
            if self.SCHEMA_NAME in {"score-v2", "owner-scorecard"}:
                from .owner_scorecard import _replay_extension_contract
            else:
                from .valuation_synthesis import _replay_extension_contract

            _replay_retained_extension_authority(self, _replay_extension_contract)

    def to_dict(self) -> dict[str, Any]:
        return {
            item.name: _serialized_value(getattr(self, item.name))
            for item in _serialized_fields(self)
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


_PRIVATE = {"serialize": False}


@dataclass(frozen=True, slots=True)
class ValuationBasisReceipt(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "valuation-basis-receipt"

    schema_version: str
    receipt_id: str
    issuer_id: str
    security_id: str
    ticker: str
    listing_mic: str
    share_class: str
    currency: str
    model_unit: str
    share_unit: str
    valuation_date: str
    twelve_month_date: str
    current_shares: str
    twelve_month_shares: str
    current_nonoperating_assets: str
    current_nonequity_claims: str
    current_net_financial_obligations_fact_id: str
    current_net_financial_obligations: str
    twelve_month_nonoperating_assets: str
    twelve_month_nonequity_claims: str
    twelve_month_net_financial_obligations: str
    core_archive_fingerprint: str
    core_result_sha256: str
    run_input_receipt_fingerprint: str
    price_blind_input_fingerprint: str
    market_reference_snapshot_fingerprint: str
    share_basis_decision_fingerprint: str
    review_authority_fingerprint: str
    reviewer_id: str
    reviewed_at: str
    evidence_ids: tuple[str, ...]
    _run_result: object = field(repr=False, metadata=_PRIVATE)
    _review_authority: object = field(repr=False, metadata=_PRIVATE)


@dataclass(frozen=True, slots=True)
class ForwardReOIInputReceipt(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "forward-reoi-input-receipt"

    schema_version: str
    receipt_id: str
    issuer_id: str
    valuation_date: str
    basis_receipt_fingerprint: str
    run_input_receipt_fingerprint: str
    price_blind_input_fingerprint: str
    assumption_ledger_fingerprint: str
    current_noa_fact_id: str
    current_noa: str
    current_nfo_fact_id: str
    current_nfo: str
    scenarios: tuple[FrozenMap, ...]
    review_authority_fingerprint: str
    reviewer_id: str
    reviewed_at: str
    evidence_ids: tuple[str, ...]
    _run_result: object = field(repr=False, metadata=_PRIVATE)
    _basis_authority: object = field(repr=False, metadata=_PRIVATE)
    _review_authority: object = field(repr=False, metadata=_PRIVATE)


@dataclass(frozen=True, slots=True)
class ForwardReOIValuationResult(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "forward-reoi-valuation-result"

    schema_version: str
    result_id: str
    extension_label: str
    status: str
    issuer_id: str
    basis_receipt: FrozenMap
    input_receipt: FrozenMap
    scenarios: tuple[FrozenMap, ...]
    issue_codes: tuple[str, ...]
    _run_result: object = field(repr=False, metadata=_PRIVATE)
    _basis_authority: object = field(repr=False, metadata=_PRIVATE)
    _input_authority: object = field(repr=False, metadata=_PRIVATE)

    def scenario(self, name: str) -> FrozenMap:
        matches = tuple(item for item in self.scenarios if item["name"] == name)
        if len(matches) != 1:
            raise KeyError(f"forward ReOI scenario is unavailable: {name}")
        return matches[0]


@dataclass(frozen=True, slots=True)
class ComparableInputReceipt(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "comparable-input-receipt"

    schema_version: str
    receipt_id: str
    issuer_id: str
    valuation_date: str
    basis_receipt_fingerprint: str
    run_input_receipt_fingerprint: str
    peer_authority_fingerprint: str
    peer_graph_fingerprints: FrozenMap
    forecast_review_fingerprint: str
    futu_peer_evidence_set_fingerprint: str
    selection_frozen_at: str
    peer_set: tuple[FrozenMap, ...]
    metric_inputs: tuple[FrozenMap, ...]
    reviewer_id: str
    reviewed_at: str
    evidence_ids: tuple[str, ...]
    _run_result: object = field(repr=False, metadata=_PRIVATE)
    _basis_authority: object = field(repr=False, metadata=_PRIVATE)
    _peer_authority: object = field(repr=False, metadata=_PRIVATE)


@dataclass(frozen=True, slots=True)
class ComparableValuationResult(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "comparable-valuation-result"

    schema_version: str
    result_id: str
    extension_label: str
    status: str
    issuer_id: str
    basis_receipt: FrozenMap
    input_receipt: FrozenMap
    metric_results: tuple[FrozenMap, ...]
    scenarios: tuple[FrozenMap, ...]
    valid_peer_count: int
    valid_multiple_count: int
    issue_codes: tuple[str, ...]
    _run_result: object = field(repr=False, metadata=_PRIVATE)
    _basis_authority: object = field(repr=False, metadata=_PRIVATE)
    _input_authority: object = field(repr=False, metadata=_PRIVATE)

    def scenario(self, name: str) -> FrozenMap:
        matches = tuple(item for item in self.scenarios if item["name"] == name)
        if len(matches) != 1:
            raise KeyError(f"comparable scenario is unavailable: {name}")
        return matches[0]


@dataclass(frozen=True, slots=True)
class CompositeValuationResult(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "composite-valuation-result"

    schema_version: str
    result_id: str
    extension_label: str
    status: str
    issuer_id: str
    basis_receipt: FrozenMap
    core_archive_fingerprint: str
    core_result_sha256: str
    run_input_receipt_fingerprint: str
    panel_fingerprints: FrozenMap
    panel_scenarios: FrozenMap
    current_intrinsic_value: str | None
    twelve_month_target: str | None
    current_relative_dispersion: str | None
    twelve_month_relative_dispersion: str | None
    market_price: str
    margin_of_safety: str | None
    twelve_month_upside: str | None
    contested: bool
    recommendation_eligible: bool
    issue_codes: tuple[str, ...]
    _run_result: object = field(repr=False, metadata=_PRIVATE)
    _basis_authority: object = field(repr=False, metadata=_PRIVATE)
    _forward_authority: object | None = field(repr=False, metadata=_PRIVATE)
    _comparable_authority: object | None = field(repr=False, metadata=_PRIVATE)


@dataclass(frozen=True, slots=True)
class ScoreV2(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "score-v2"

    schema_version: str
    score_id: str
    extension_label: str
    issuer_id: str
    as_of_date: str
    lens: str
    status: str
    research_bundle_fingerprint: str
    contract_graph_fingerprint: str
    review_authority_fingerprint: str
    composite_valuation_fingerprint: str
    components: tuple[FrozenMap, ...]
    total_score: str | None
    confidence_percent: str | None
    red_flags: tuple[FrozenMap, ...]
    missing_evidence: tuple[str, ...]
    _composite_authority: object = field(repr=False, metadata=_PRIVATE)
    _review_authority: object = field(repr=False, metadata=_PRIVATE)


@dataclass(frozen=True, slots=True)
class OwnerScorecard(ExtensionContract):
    SCHEMA_NAME: ClassVar[str] = "owner-scorecard"

    schema_version: str
    scorecard_id: str
    extension_label: str
    issuer_id: str
    as_of_date: str
    status: str
    research_bundle_fingerprint: str
    composite_valuation_fingerprint: str
    lens_scores: tuple[FrozenMap, ...]
    overall_score: str | None
    confidence_percent: str | None
    recommendation: str
    current_intrinsic_value: str | None
    market_price: str
    margin_of_safety: str | None
    twelve_month_upside: str | None
    critical_red_flags: tuple[FrozenMap, ...]
    issue_codes: tuple[str, ...]
    _composite_authority: object = field(repr=False, metadata=_PRIVATE)
    _score_authorities: tuple[object, ...] = field(repr=False, metadata=_PRIVATE)


__all__ = (
    "ComparableInputReceipt",
    "ComparableValuationResult",
    "CompositeValuationResult",
    "EXTENSION_SCHEMA_NAMES",
    "ExtensionAuthorityError",
    "ExtensionContract",
    "ForwardReOIInputReceipt",
    "ForwardReOIValuationResult",
    "NamedHumanReviewAuthority",
    "OwnerScorecard",
    "ScoreV2",
    "ValuationBasisReceipt",
    "build_named_human_review_authority",
    "extension_schema_directory",
    "load_extension_schema",
    "validate_extension_payload",
)
