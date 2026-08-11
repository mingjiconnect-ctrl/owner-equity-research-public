"""Internal projection of governed research evidence into pinned-kernel numerics.

This module deliberately does not import the valuation kernel.  It translates the
already-reviewed current-common-share lineage into the exact shapes accepted by the
pinned rc.2 FactLedger while retaining an attestation over every corroborating research
object.  In particular, a canonical cross-source event Fact is never laundered into a
kernel ``raw`` Fact: one reviewed raw member represents the event numerically and all
members remain bound by the evidence attestation.
"""

from __future__ import annotations

import json
import math
import struct
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from .contracts import Fact, SourceDocument
from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .valuation_fact_mapping import _source_is_registered, _source_ref
from .valuation_market_snapshot import PreparedMarketReference


class KernelProjectionError(ValueError):
    """Raised when research evidence cannot be represented exactly by rc.2."""


_ISSUED_LESS_TREASURY_FORMULA = "common_shares_issued - treasury_shares"
_COMPLETED_EVENT_ROLLFORWARD_FORMULA = (
    "common_shares_outstanding + completed_issuances_and_settlements "
    "- completed_repurchases_and_retirements"
)
_RESEARCH_ISSUED_LESS_TREASURY = "issued-less-treasury/1.0.0"
_RESEARCH_ROLLFORWARD_DERIVATIONS = frozenset(
    {"completed-event-rollforward/1.0.0", "completed-event-rollforward/2.0.0"}
)
_EVENT_CONCEPTS = {
    "common_shares_issued_completed": "completed_common_share_issuance",
    "common_shares_repurchased_completed": "completed_common_share_repurchase",
    "common_shares_retired_or_cancelled_completed": "completed_common_share_retirement",
    "option_shares_exercised_completed": "completed_option_exercise_shares",
    "rsu_shares_settled_completed": "completed_rsu_settlement_shares",
    "acquisition_consideration_shares_issued_completed": (
        "completed_common_share_issuance"
    ),
}
_SPECIALIST_EVENT_CONCEPTS = frozenset(
    {
        "convertible_shares_converted_completed",
        "warrant_shares_exercised_completed",
    }
)
_EVENT_SIGNS = {
    "completed_common_share_issuance": 1,
    "completed_common_share_repurchase": -1,
    "completed_common_share_retirement": -1,
    "completed_option_exercise_shares": 1,
    "completed_rsu_settlement_shares": 1,
}


def _checked_binary64(value: object, label: str) -> float:
    try:
        projected = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise KernelProjectionError(f"{label} cannot be represented as binary64") from exc
    if not math.isfinite(projected):
        raise KernelProjectionError(f"{label} cannot be represented as finite binary64")
    if projected != 0.0 and abs(projected) < sys.float_info.min:
        raise KernelProjectionError(f"{label} is subnormal in binary64")
    return projected


def _canonical_decimal(value: object, label: str, *, allow_zero: bool = False) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise KernelProjectionError(f"{label} is not an exact decimal") from exc
    if not parsed.is_finite() or (parsed < 0 if allow_zero else parsed <= 0):
        raise KernelProjectionError(f"{label} must be finite and positive")
    return parsed


@dataclass(frozen=True, slots=True)
class KernelNumericProjectionWitness:
    """Replayable witness for one Decimal-to-JSON-binary64 projection."""

    label: str
    authoritative_decimal: str
    scale_divisor_decimal: str
    model_decimal: str
    canonical_json_number_token: str
    binary64_hex: str
    exact_binary64_decimal: str
    shortest_roundtrip_decimal: str

    def __post_init__(self) -> None:
        authoritative = _canonical_decimal(
            self.authoritative_decimal,
            f"{self.label} authoritative value",
            allow_zero=True,
        )
        divisor = _canonical_decimal(
            self.scale_divisor_decimal,
            f"{self.label} scale divisor",
        )
        model = _canonical_decimal(
            self.model_decimal,
            f"{self.label} model value",
            allow_zero=True,
        )
        if authoritative / divisor != model:
            raise ValueError("numeric projection scale does not replay")
        try:
            parsed_json = json.loads(self.canonical_json_number_token)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("numeric projection JSON token is invalid") from exc
        if isinstance(parsed_json, bool) or not isinstance(parsed_json, (int, float)):
            raise ValueError("numeric projection JSON token is not a number")
        try:
            projected = _checked_binary64(parsed_json, f"{self.label} JSON projection")
        except KernelProjectionError as exc:
            raise ValueError(str(exc)) from exc
        if self.canonical_json_number_token != json.dumps(
            projected,
            allow_nan=False,
            separators=(",", ":"),
        ):
            raise ValueError("numeric projection JSON token is not canonical")
        if struct.pack(">d", projected).hex() != self.binary64_hex:
            raise ValueError("numeric projection binary64 witness mismatch")
        if format(Decimal.from_float(projected), "f") != self.exact_binary64_decimal:
            raise ValueError("numeric projection exact binary64 decimal mismatch")
        if repr(projected) != self.shortest_roundtrip_decimal:
            raise ValueError("numeric projection round-trip decimal mismatch")
        if Decimal(str(projected)) != model:
            raise ValueError("authoritative Decimal does not round-trip through binary64")
        replayed = json.loads(
            json.dumps(projected, allow_nan=False, separators=(",", ":"))
        )
        if struct.pack(">d", float(replayed)).hex() != self.binary64_hex:
            raise ValueError("canonical JSON changes the projected binary64 value")

    @classmethod
    def compile(
        cls,
        *,
        label: str,
        authoritative_decimal: Decimal,
        scale_divisor: Decimal = Decimal(1),
    ) -> KernelNumericProjectionWitness:
        model = authoritative_decimal / scale_divisor
        projected = _checked_binary64(model, label)
        if Decimal(str(projected)) != model:
            raise KernelProjectionError(
                f"{label} cannot be transported to rc.2 without numeric drift"
            )
        token = json.dumps(projected, allow_nan=False, separators=(",", ":"))
        return cls(
            label=label,
            authoritative_decimal=format(authoritative_decimal, "f"),
            scale_divisor_decimal=format(scale_divisor, "f"),
            model_decimal=format(model, "f"),
            canonical_json_number_token=token,
            binary64_hex=struct.pack(">d", projected).hex(),
            exact_binary64_decimal=format(Decimal.from_float(projected), "f"),
            shortest_roundtrip_decimal=repr(projected),
        )

    @classmethod
    def compile_from_projected_binary64(
        cls,
        *,
        label: str,
        authoritative_decimal: Decimal,
        projected_value: float,
        scale_divisor: Decimal = Decimal(1),
    ) -> KernelNumericProjectionWitness:
        """Bind a projection calculated from upstream binary64 operands."""

        model = authoritative_decimal / scale_divisor
        projected_value = _checked_binary64(projected_value, label)
        if Decimal(str(projected_value)) != model:
            raise KernelProjectionError(
                f"{label} upstream binary64 arithmetic does not equal the authoritative Decimal"
            )
        token = json.dumps(projected_value, allow_nan=False, separators=(",", ":"))
        return cls(
            label=label,
            authoritative_decimal=format(authoritative_decimal, "f"),
            scale_divisor_decimal=format(scale_divisor, "f"),
            model_decimal=format(model, "f"),
            canonical_json_number_token=token,
            binary64_hex=struct.pack(">d", projected_value).hex(),
            exact_binary64_decimal=format(Decimal.from_float(projected_value), "f"),
            shortest_roundtrip_decimal=repr(projected_value),
        )

    @property
    def kernel_value(self) -> float:
        return float(json.loads(self.canonical_json_number_token))

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class CurrentShareKernelProjection:
    """Closed rc.2 current-share fragment plus its research evidence attestation."""

    status: str
    evidence_kind: str | None
    current_share_fact_id: str | None
    sources: tuple[FrozenMap, ...]
    facts: tuple[FrozenMap, ...]
    numeric_witnesses: tuple[KernelNumericProjectionWitness, ...]
    arithmetic_steps: tuple[FrozenMap, ...]
    research_evidence_attestation: FrozenMap | None
    research_evidence_sha256: str | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"eligible", "specialist_required", "blocked"}:
            raise ValueError("current-share kernel projection status is invalid")
        sources = tuple(
            sorted((freeze(item) for item in self.sources), key=lambda item: item["source_id"])
        )
        facts = tuple(
            sorted((freeze(item) for item in self.facts), key=lambda item: item["fact_id"])
        )
        witnesses = tuple(sorted(self.numeric_witnesses, key=lambda item: item.label))
        arithmetic = tuple(freeze(item) for item in self.arithmetic_steps)
        attestation = (
            freeze(self.research_evidence_attestation)
            if self.research_evidence_attestation is not None
            else None
        )
        issues = tuple(sorted(set(self.issue_codes)))
        if len(sources) != len({item["source_id"] for item in sources}):
            raise ValueError("projected current-share sources repeat an ID")
        if len(facts) != len({item["fact_id"] for item in facts}):
            raise ValueError("projected current-share Facts repeat an ID")
        if self.status == "eligible":
            if (
                not self.current_share_fact_id
                or self.evidence_kind
                not in {
                    "direct_point_in_time",
                    "issued_less_treasury",
                    "completed_event_rollforward",
                }
                or not sources
                or not facts
                or not witnesses
                or not arithmetic
                or attestation is None
                or not self.research_evidence_sha256
                or canonical_sha256(attestation) != self.research_evidence_sha256
                or issues
                or self.current_share_fact_id not in {item["fact_id"] for item in facts}
            ):
                raise ValueError("eligible current-share projection is incomplete")
        elif any(
            (
                self.current_share_fact_id,
                self.evidence_kind,
                sources,
                facts,
                witnesses,
                arithmetic,
                attestation,
                self.research_evidence_sha256,
            )
        ) or not issues:
            raise ValueError("non-eligible current-share projection promoted evidence")
        object.__setattr__(self, "sources", sources)
        object.__setattr__(self, "facts", facts)
        object.__setattr__(self, "numeric_witnesses", witnesses)
        object.__setattr__(self, "arithmetic_steps", arithmetic)
        object.__setattr__(self, "research_evidence_attestation", attestation)
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _blocked(*issues: str, specialist: bool = False) -> CurrentShareKernelProjection:
    return CurrentShareKernelProjection(
        status="specialist_required" if specialist else "blocked",
        evidence_kind=None,
        current_share_fact_id=None,
        sources=(),
        facts=(),
        numeric_witnesses=(),
        arithmetic_steps=(),
        research_evidence_attestation=None,
        research_evidence_sha256=None,
        issue_codes=tuple(issues),
    )


def _document_for_fact(prepared: PreparedMarketReference, fact: Fact) -> SourceDocument:
    matches = tuple(
        item
        for item in prepared.graph.documents
        if item.document_id == fact.source_document_id
    )
    if len(matches) != 1:
        raise KernelProjectionError("share Fact source is unavailable or ambiguous")
    document = matches[0]
    if (
        document.issuer_id != fact.issuer_id
        or document.published_date > prepared.snapshot.data_cutoff_date
        or not _source_is_registered(document)
    ):
        raise KernelProjectionError("share Fact source is not eligible formal evidence")
    return document


def _source_and_raw_fact(
    prepared: PreparedMarketReference,
    fact: Fact,
    *,
    concept: str,
) -> tuple[dict[str, Any], dict[str, Any], KernelNumericProjectionWitness]:
    if (
        fact.value_type != "number"
        or fact.unit != "shares"
        or fact.currency is not None
        or fact.derivation is not None
        or fact.parent_fact_ids
        or fact.period["start"] is not None
        or fact.period["end"] is None
        or fact.confidence not in {"high", "medium"}
    ):
        raise KernelProjectionError("raw share Fact semantics are not kernel eligible")
    document = _document_for_fact(prepared, fact)
    witness = KernelNumericProjectionWitness.compile(
        label=f"share:{fact.fact_id}",
        authoritative_decimal=_canonical_decimal(fact.value, "share Fact", allow_zero=True),
        scale_divisor=Decimal(1_000_000),
    )
    source = _source_ref(document)
    kernel_fact = {
        "fact_id": fact.fact_id,
        "concept": concept,
        "value": witness.kernel_value,
        "unit": "millions shares",
        "category": "share_count",
        "source_id": source["source_id"],
        "source_location": fact.source_locator,
        "as_of_date": fact.period["end"],
        "currency": None,
        "period_start": None,
        "period_end": None,
        "confidence": fact.confidence,
        "raw": True,
        "parent_fact_ids": [],
        "derivation": None,
        "equity_bridge_role": None,
    }
    return source, kernel_fact, witness


def _derived_share_fact(
    fact: Fact,
    *,
    parent_ids: tuple[str, ...],
    source_id: str,
    derivation: str,
    witness: KernelNumericProjectionWitness,
) -> dict[str, Any]:
    if fact.period["start"] is not None or fact.period["end"] is None:
        raise KernelProjectionError("derived share Fact is not point-in-time")
    return {
        "fact_id": fact.fact_id,
        "concept": "common_shares_outstanding",
        "value": witness.kernel_value,
        "unit": "millions shares",
        "category": "share_count",
        "source_id": source_id,
        "source_location": fact.source_locator,
        "as_of_date": fact.period["end"],
        "currency": None,
        "period_start": None,
        "period_end": None,
        "confidence": fact.confidence,
        "raw": False,
        "parent_fact_ids": list(parent_ids),
        "derivation": derivation,
        "equity_bridge_role": None,
    }


def _fact_index(prepared: PreparedMarketReference) -> dict[str, Fact]:
    index: dict[str, Fact] = {}
    for item in prepared.graph.facts:
        if item.fact_id in index and index[item.fact_id] != item:
            raise KernelProjectionError("prepared graph repeats a conflicting Fact ID")
        index[item.fact_id] = item
    output = prepared.current_shares.output_fact
    if output is not None:
        if output.fact_id in index and index[output.fact_id] != output:
            raise KernelProjectionError("current-share output collides with graph evidence")
        index[output.fact_id] = output
    canonical = prepared.current_shares.canonical_rollforward
    if canonical is not None:
        for materialization in canonical.materializations:
            item = materialization.canonical_event_fact
            if item.fact_id in index and index[item.fact_id] != item:
                raise KernelProjectionError("canonical event Fact collides with graph evidence")
            index[item.fact_id] = item
    return index


def _project_opening(
    prepared: PreparedMarketReference,
    fact: Fact,
    index: dict[str, Fact],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[KernelNumericProjectionWitness]]:
    if fact.derivation is None:
        source, raw, witness = _source_and_raw_fact(
            prepared,
            fact,
            concept="common_shares_outstanding",
        )
        return [source], [raw], [witness]
    if fact.derivation != _RESEARCH_ISSUED_LESS_TREASURY:
        raise KernelProjectionError("roll-forward opening uses an unsupported lineage")
    if len(fact.parent_fact_ids) != 2:
        raise KernelProjectionError("issued-minus-treasury opening lacks two parents")
    parents = [index.get(item) for item in fact.parent_fact_ids]
    if any(item is None for item in parents):
        raise KernelProjectionError("issued-minus-treasury parent is unavailable")
    by_concept = {item.concept: item for item in parents if item is not None}
    if set(by_concept) != {"common_shares_issued", "treasury_shares"}:
        raise KernelProjectionError("issued-minus-treasury parent concepts are invalid")
    if any(item.period["end"] != fact.period["end"] for item in by_concept.values()):
        raise KernelProjectionError(
            "issued-minus-treasury parents do not share the output measurement date"
        )
    sources: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    witnesses: list[KernelNumericProjectionWitness] = []
    for concept in ("common_shares_issued", "treasury_shares"):
        source, raw, witness = _source_and_raw_fact(
            prepared,
            by_concept[concept],
            concept=concept,
        )
        sources.append(source)
        facts.append(raw)
        witnesses.append(witness)
    output_witness = KernelNumericProjectionWitness.compile(
        label=f"share:{fact.fact_id}",
        authoritative_decimal=_canonical_decimal(fact.value, "issued share output"),
        scale_divisor=Decimal(1_000_000),
    )
    issued_value = next(
        item["value"] for item in facts if item["concept"] == "common_shares_issued"
    )
    treasury_value = next(item["value"] for item in facts if item["concept"] == "treasury_shares")
    if output_witness.kernel_value != issued_value - treasury_value:
        raise KernelProjectionError("issued-minus-treasury projection is not exact in binary64")
    output_source = _source_ref(_document_for_fact(prepared, fact))
    sources.append(output_source)
    facts.append(
        _derived_share_fact(
            fact,
            parent_ids=(
                by_concept["common_shares_issued"].fact_id,
                by_concept["treasury_shares"].fact_id,
            ),
            source_id=output_source["source_id"],
            derivation=_ISSUED_LESS_TREASURY_FORMULA,
            witness=output_witness,
        )
    )
    witnesses.append(output_witness)
    return sources, facts, witnesses


def _unique_by_id(items: list[dict[str, Any]], field: str) -> tuple[FrozenMap, ...]:
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        identifier = str(item[field])
        if identifier in index and canonical_sha256(index[identifier]) != canonical_sha256(item):
            raise KernelProjectionError(f"projected object collides at {identifier}")
        index[identifier] = item
    return tuple(freeze(index[key]) for key in sorted(index))


def project_current_share_lineage(
    prepared: PreparedMarketReference,
) -> CurrentShareKernelProjection:
    """Project the accepted direct/issued/V2 roll-forward lineage into rc.2 Facts."""

    current = prepared.current_shares
    output = current.output_fact
    decision = current.share_basis_decision
    if current.status != "eligible" or output is None or decision is None:
        return _blocked("current_share_not_eligible")
    if output.fact_id != prepared.snapshot.share_basis["shares_outstanding_fact_id"]:
        return _blocked("snapshot_current_share_mismatch")
    if output.period["end"] != prepared.snapshot.trading_date:
        return _blocked("current_share_date_mismatch")
    selected = tuple(item for item in current.path_decisions if item.status == "selected")
    if len(selected) != 1:
        return _blocked("current_share_path_ambiguous")
    evidence_kind = selected[0].path_kind
    index = _fact_index(prepared)
    sources: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    witnesses: list[KernelNumericProjectionWitness] = []
    arithmetic_steps: list[dict[str, Any]] = []
    attestation: dict[str, Any] = {
        "current_share_compilation_fingerprint": current.fingerprint,
        "share_basis_decision_fingerprint": decision.fingerprint,
        "evidence_closure_fingerprint": getattr(
            current.evidence_closure,
            "closure_sha256",
            getattr(current.evidence_closure, "fingerprint", None),
        ),
        "path_kind": evidence_kind,
        "objects": [],
    }
    try:
        if evidence_kind == "direct_point_in_time":
            source, raw, witness = _source_and_raw_fact(
                prepared,
                output,
                concept="common_shares_outstanding",
            )
            sources.append(source)
            facts.append(raw)
            witnesses.append(witness)
            attestation["objects"].append(("Fact", output.fact_id, output.fingerprint))
            arithmetic_steps.append(
                {
                    "step": 0,
                    "operation": "direct",
                    "input_fact_ids": [output.fact_id],
                    "output_binary64_hex": witness.binary64_hex,
                }
            )
        elif evidence_kind == "issued_less_treasury":
            if output.derivation != _RESEARCH_ISSUED_LESS_TREASURY:
                raise KernelProjectionError("issued path derivation changed")
            projected = _project_opening(prepared, output, index)
            sources.extend(projected[0])
            facts.extend(projected[1])
            witnesses.extend(projected[2])
            attestation["objects"].extend(
                ("Fact", item.fact_id, item.fingerprint)
                for item in (output, *(index[parent] for parent in output.parent_fact_ids))
            )
            issued = next(item for item in facts if item["concept"] == "common_shares_issued")
            treasury = next(item for item in facts if item["concept"] == "treasury_shares")
            arithmetic_steps.append(
                {
                    "step": 0,
                    "operation": "issued_less_treasury",
                    "input_fact_ids": [issued["fact_id"], treasury["fact_id"]],
                    "input_binary64_hex": [
                        struct.pack(">d", float(issued["value"])).hex(),
                        struct.pack(">d", float(treasury["value"])).hex(),
                    ],
                    "output_binary64_hex": next(
                        item.binary64_hex
                        for item in witnesses
                        if item.label == f"share:{output.fact_id}"
                    ),
                }
            )
        elif evidence_kind == "completed_event_rollforward":
            rollforward = current.canonical_rollforward
            if (
                rollforward is None
                or output.derivation not in _RESEARCH_ROLLFORWARD_DERIVATIONS
                or rollforward.output_share_fact_id != output.fact_id
            ):
                raise KernelProjectionError("V2 canonical roll-forward is unavailable")
            opening = index.get(rollforward.opening_share_fact_id)
            if opening is None:
                raise KernelProjectionError("roll-forward opening Fact is unavailable")
            opening_sources, opening_facts, opening_witnesses = _project_opening(
                prepared,
                opening,
                index,
            )
            sources.extend(opening_sources)
            facts.extend(opening_facts)
            witnesses.extend(opening_witnesses)
            parent_ids = [opening.fact_id]
            replay = next(
                item["value"]
                for item in opening_facts
                if item["fact_id"] == opening.fact_id
            )
            arithmetic_steps.append(
                {
                    "step": 0,
                    "operation": "opening",
                    "input_fact_ids": [opening.fact_id],
                    "output_binary64_hex": struct.pack(">d", float(replay)).hex(),
                }
            )
            for materialization in sorted(
                rollforward.materializations,
                key=lambda item: item.group_id,
            ):
                canonical = materialization.canonical_event_fact
                if canonical.concept in _SPECIALIST_EVENT_CONCEPTS:
                    return _blocked("warrant_event_requires_specialist", specialist=True)
                kernel_concept = _EVENT_CONCEPTS.get(canonical.concept)
                if kernel_concept is None:
                    raise KernelProjectionError("share event has no rc.2 concept mapping")
                members = tuple(sorted(materialization.members, key=lambda item: item.member_id))
                member_facts = tuple(item.fact for item in members)
                if (
                    not members
                    or canonical.period["end"] is None
                    or set(canonical.parent_fact_ids)
                    != {item.fact_id for item in member_facts}
                    or any(
                        item.concept != canonical.concept
                        or item.period["end"] != canonical.period["end"]
                        or Decimal(str(item.value)) != Decimal(str(canonical.value))
                        or item.unit != canonical.unit
                        or item.currency != canonical.currency
                        or item.derivation is not None
                        or item.parent_fact_ids
                        for item in member_facts
                    )
                ):
                    raise KernelProjectionError(
                        "canonical event members do not replay one reviewed economic event"
                    )
                representatives = tuple(
                    item
                    for item in members
                    if item.source_document_id == materialization.primary_source_document_id
                )
                if len(representatives) != 1:
                    raise KernelProjectionError(
                        "canonical event requires exactly one primary raw representative"
                    )
                representative = representatives[0]
                if not (
                    opening.period["end"]
                    < representative.fact.period["end"]
                    <= output.period["end"]
                ):
                    raise KernelProjectionError(
                        "canonical event falls outside the roll-forward window"
                    )
                source, raw, witness = _source_and_raw_fact(
                    prepared,
                    representative.fact,
                    concept=kernel_concept,
                )
                sources.append(source)
                facts.append(raw)
                witnesses.append(witness)
                parent_ids.append(raw["fact_id"])
                replay += _EVENT_SIGNS[kernel_concept] * raw["value"]
                arithmetic_steps.append(
                    {
                        "step": len(arithmetic_steps),
                        "operation": (
                            "add" if _EVENT_SIGNS[kernel_concept] > 0 else "subtract"
                        ),
                        "group_id": materialization.group_id,
                        "representative_fact_id": raw["fact_id"],
                        "corroborating_member_fact_ids": sorted(
                            item.fact_id for item in members
                        ),
                        "input_binary64_hex": witness.binary64_hex,
                        "running_output_binary64_hex": struct.pack(">d", float(replay)).hex(),
                    }
                )
                attestation["objects"].append(
                    (
                        "CanonicalShareEventGroup",
                        materialization.group_id,
                        materialization.materialization_fingerprint,
                    )
                )
                attestation["objects"].extend(
                    ("Fact", item.fact.fact_id, item.fact.fingerprint) for item in members
                )
                attestation["objects"].extend(
                    (
                        "SourceDocument",
                        item.source_document.document_id,
                        item.source_document.fingerprint,
                    )
                    for item in members
                )
            output_witness = KernelNumericProjectionWitness.compile(
                label=f"share:{output.fact_id}",
                authoritative_decimal=_canonical_decimal(output.value, "roll-forward output"),
                scale_divisor=Decimal(1_000_000),
            )
            if output_witness.kernel_value != replay:
                raise KernelProjectionError("roll-forward projection is not exact in binary64")
            output_source = _source_ref(_document_for_fact(prepared, output))
            sources.append(output_source)
            facts.append(
                _derived_share_fact(
                    output,
                    parent_ids=tuple(parent_ids),
                    source_id=output_source["source_id"],
                    derivation=_COMPLETED_EVENT_ROLLFORWARD_FORMULA,
                    witness=output_witness,
                )
            )
            witnesses.append(output_witness)
            attestation["objects"].extend(
                (
                    ("Fact", output.fact_id, output.fingerprint),
                    ("Fact", opening.fact_id, opening.fingerprint),
                )
            )
        else:
            raise KernelProjectionError("selected current-share path is not supported")
        source_items = _unique_by_id(sources, "source_id")
        fact_items = _unique_by_id(facts, "fact_id")
        fact_ids = {item["fact_id"] for item in fact_items}
        if output.fact_id not in fact_ids:
            raise KernelProjectionError("projected current-share output is missing")
        attestation["objects"] = sorted(set(tuple(item) for item in attestation["objects"]))
        closure_objects = getattr(current.evidence_closure, "object_fingerprints", ())
        attestation["closure_objects"] = sorted(tuple(item) for item in closure_objects)
        attestation["arithmetic_steps"] = arithmetic_steps
        return CurrentShareKernelProjection(
            status="eligible",
            evidence_kind=evidence_kind,
            current_share_fact_id=output.fact_id,
            sources=source_items,
            facts=fact_items,
            numeric_witnesses=tuple(witnesses),
            arithmetic_steps=tuple(freeze(item) for item in arithmetic_steps),
            research_evidence_attestation=freeze(attestation),
            research_evidence_sha256=canonical_sha256(attestation),
            issue_codes=(),
        )
    except (KernelProjectionError, KeyError, ValueError) as exc:
        return _blocked(f"current_share_projection_blocked:{type(exc).__name__}")


__all__ = ()
