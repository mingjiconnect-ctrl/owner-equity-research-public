from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import date
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from typing import Any

from .contracts import Claim, Fact, SourceDocument
from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .futu_receipts import (
    FUTU_SCHEMA_VERSION,
    FutuCrossCheckReceipt,
    FutuEvidenceBundle,
    FutuObservation,
    FutuReceiptError,
    content_identity,
)
from .futu_sidecar import load_financial_field_registry
from .validation import ContractGraph, ContractGraphError

_OFFICIAL_AUTHORITIES = frozenset({"primary_regulatory", "company_primary"})
_OFFICIAL_OBJECT_TYPES = frozenset({"Fact", "SourceDocument", "Claim"})
_RESOLUTIONS = frozenset(
    {
        "official_evidence_confirmed_vendor_rejected",
        "vendor_mapping_corrected_new_run_required",
        "official_evidence_correction_requires_new_run",
        "not_comparable_confirmed",
    }
)
_CANONICAL_DECIMAL = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z"
)
_SPLIT_CONCEPTS = frozenset(
    {"stock_split_completed", "reverse_stock_split_completed"}
)


def split_observation_matches_official_period(
    vendor: FutuObservation,
    official_period: Mapping[str, Any],
) -> bool:
    """Match exact periods or the documented US announcement-only 3236 shape."""

    vendor_period = to_json_value(vendor.period)
    official = to_json_value(official_period)
    if vendor_period == official:
        return True
    if (
        vendor.canonical_concept not in _SPLIT_CONCEPTS
        or vendor.qualifiers.get("effective_date") is not None
        or official.get("start") is not None
    ):
        return False
    announcement = vendor.qualifiers.get("announcement_date")
    official_end = official.get("end")
    if (
        not isinstance(announcement, str)
        or not isinstance(official_end, str)
        or vendor_period != {"start": None, "end": announcement}
    ):
        return False
    try:
        announcement_date = date.fromisoformat(announcement)
        effective_date = date.fromisoformat(official_end)
    except ValueError:
        return False
    days = (effective_date - announcement_date).days
    return 0 <= days <= 366


class FutuCrossCheckError(ValueError):
    """Raised when a vendor cross-check attempts to cross an authority boundary."""


@dataclass(frozen=True, slots=True)
class OfficialEvidenceOperand:
    """Exact graph-owned SEC/IR object plus its deterministic comparison projection."""

    official_object: Fact | Claim | SourceDocument
    contract_graph_fingerprint: str
    object_type: str
    object_id: str
    object_fingerprint: str
    authority: str
    issuer_id: str
    canonical_concept: str
    period: FrozenMap
    value_type: str
    value: str | bool | None
    unit: str | None
    currency: str | None
    reported_precision_decimal: str | None = None
    operand_fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.object_type not in _OFFICIAL_OBJECT_TYPES:
            raise FutuCrossCheckError("official evidence object type is invalid")
        if self.authority not in _OFFICIAL_AUTHORITIES:
            raise FutuCrossCheckError("only SEC/IR authority may occupy the official operand")
        if not self.object_id or not self.issuer_id or not self.canonical_concept:
            raise FutuCrossCheckError("official evidence identity is incomplete")
        _require_sha256(self.object_fingerprint, "object_fingerprint")
        _require_sha256(self.contract_graph_fingerprint, "contract_graph_fingerprint")
        expected_type = type(self.official_object).__name__
        if expected_type != self.object_type:
            raise FutuCrossCheckError("official object type does not bind the retained object")
        if self.official_object.fingerprint != self.object_fingerprint:
            raise FutuCrossCheckError("official object fingerprint does not bind retained bytes")
        object.__setattr__(self, "period", freeze(self.period))
        if set(self.period) != {"start", "end"}:
            raise FutuCrossCheckError("official evidence period must contain start and end")
        if any(
            value is not None and not isinstance(value, str) for value in self.period.values()
        ):
            raise FutuCrossCheckError("official evidence period values must be dates or null")
        if (
            self.period["start"] is not None
            and self.period["end"] is not None
            and self.period["start"] > self.period["end"]
        ):
            raise FutuCrossCheckError("official evidence period is reversed")
        if self.value_type == "number":
            if not isinstance(self.value, str):
                raise FutuCrossCheckError("official numeric evidence must use a decimal string")
            _decimal(self.value, "official value")
        elif self.value_type == "text":
            if not isinstance(self.value, str):
                raise FutuCrossCheckError("official text evidence must use a string")
        elif self.value_type == "boolean":
            if not isinstance(self.value, bool):
                raise FutuCrossCheckError("official boolean evidence must use boolean")
        elif self.value_type == "null":
            if self.value is not None:
                raise FutuCrossCheckError("official null evidence must use null")
        else:
            raise FutuCrossCheckError("official evidence value_type is invalid")
        if self.reported_precision_decimal is not None:
            precision = _decimal(self.reported_precision_decimal, "reported precision")
            if precision <= 0 or self.value_type != "number":
                raise FutuCrossCheckError(
                    "reported precision must be positive and attached to numeric evidence"
                )
        expected_fingerprint = canonical_sha256(self._identity_payload())
        if self.operand_fingerprint != expected_fingerprint:
            raise FutuCrossCheckError("official operand fingerprint is invalid")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "official_object": self.official_object.to_dict(),
            "contract_graph_fingerprint": self.contract_graph_fingerprint,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "object_fingerprint": self.object_fingerprint,
            "authority": self.authority,
            "issuer_id": self.issuer_id,
            "canonical_concept": self.canonical_concept,
            "period": to_json_value(self.period),
            "value_type": self.value_type,
            "value": self.value,
            "unit": self.unit,
            "currency": self.currency,
            "reported_precision_decimal": self.reported_precision_decimal,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._identity_payload(), "operand_fingerprint": self.operand_fingerprint}

    @property
    def fingerprint(self) -> str:
        return self.operand_fingerprint


def build_official_evidence_operand(
    *,
    graph: ContractGraph,
    official_object: Fact | Claim | SourceDocument,
) -> OfficialEvidenceOperand:
    """Build an operand only from the exact validated object retained by ``graph``."""
    graph_fingerprint = contract_graph_fingerprint(graph)
    return _build_official_evidence_operand(
        graph=graph,
        official_object=official_object,
        graph_fingerprint=graph_fingerprint,
    )


def _build_official_evidence_operand(
    *,
    graph: ContractGraph,
    official_object: Fact | Claim | SourceDocument,
    graph_fingerprint: str,
) -> OfficialEvidenceOperand:
    """Build from a graph fingerprint already derived by this component."""

    _require_sha256(graph_fingerprint, "contract_graph_fingerprint")
    retained = _graph_owned_object(graph, official_object)
    documents = {item.document_id: item for item in graph.documents}

    if isinstance(retained, Fact):
        source = documents[retained.source_document_id]
        authority = source.authority_level
        canonical_concept = retained.concept
        period = retained.period
        value_type = retained.value_type
        value = _fact_value(retained)
        unit = retained.unit
        currency = retained.currency
    elif isinstance(retained, Claim):
        evidence_ids = (*retained.supporting_fact_ids, *retained.counterevidence_fact_ids)
        fact_index = {item.fact_id: item for item in graph.facts}
        evidence_sources = {
            documents[fact_index[fact_id].source_document_id].authority_level
            for fact_id in evidence_ids
        }
        if not evidence_sources or not evidence_sources.issubset(_OFFICIAL_AUTHORITIES):
            raise FutuCrossCheckError("Claim operand is not wholly supported by SEC/IR evidence")
        authority = (
            "primary_regulatory"
            if "primary_regulatory" in evidence_sources
            else "company_primary"
        )
        canonical_concept = "official_claim_statement"
        period = FrozenMap({"start": None, "end": retained.as_of_date})
        value_type = "text"
        value = retained.statement
        unit = None
        currency = None
    else:
        authority = retained.authority_level
        canonical_concept = "official_source_document_sha256"
        period = retained.period
        value_type = "text"
        value = retained.content_sha256
        unit = None
        currency = None

    if authority not in _OFFICIAL_AUTHORITIES:
        raise FutuCrossCheckError("only SEC/IR authority may occupy the official operand")
    values: dict[str, Any] = {
        "official_object": retained,
        "contract_graph_fingerprint": graph_fingerprint,
        "object_type": type(retained).__name__,
        "object_id": _official_object_id(retained),
        "object_fingerprint": retained.fingerprint,
        "authority": authority,
        "issuer_id": retained.issuer_id,
        "canonical_concept": canonical_concept,
        "period": period,
        "value_type": value_type,
        "value": value,
        "unit": unit,
        "currency": currency,
        "reported_precision_decimal": None,
    }
    identity = {
        "official_object": retained.to_dict(),
        "contract_graph_fingerprint": graph_fingerprint,
        "object_type": values["object_type"],
        "object_id": values["object_id"],
        "object_fingerprint": values["object_fingerprint"],
        "authority": values["authority"],
        "issuer_id": values["issuer_id"],
        "canonical_concept": values["canonical_concept"],
        "period": to_json_value(values["period"]),
        "value_type": values["value_type"],
        "value": values["value"],
        "unit": values["unit"],
        "currency": values["currency"],
        "reported_precision_decimal": None,
    }
    return OfficialEvidenceOperand(
        operand_fingerprint=canonical_sha256(identity),
        **values,
    )


def replay_official_evidence_operand(
    graph: ContractGraph,
    operand: OfficialEvidenceOperand,
) -> None:
    """Replay graph membership and every derived operand byte before use."""
    graph_fingerprint = contract_graph_fingerprint(graph)
    _replay_official_evidence_operand_with_graph_fingerprint(
        graph=graph,
        operand=operand,
        graph_fingerprint=graph_fingerprint,
    )


def _replay_official_evidence_operand_with_graph_fingerprint(
    *,
    graph: ContractGraph,
    operand: OfficialEvidenceOperand,
    graph_fingerprint: str,
) -> None:
    """Replay an operand against an exact component-derived graph identity."""

    _require_sha256(graph_fingerprint, "contract_graph_fingerprint")
    if operand.contract_graph_fingerprint != graph_fingerprint:
        raise FutuCrossCheckError("official operand is bound to another graph")
    candidate = _build_official_evidence_operand(
        graph=graph,
        official_object=operand.official_object,
        graph_fingerprint=graph_fingerprint,
    )
    if candidate.to_dict() != operand.to_dict():
        raise FutuCrossCheckError("official operand no longer replays from the exact graph")


def contract_graph_fingerprint(graph: ContractGraph) -> str:
    """Bind all typed collections of a validated ContractGraph, excluding its path handle."""
    try:
        graph.validate()
    except (ContractGraphError, OSError, ValueError) as exc:
        raise FutuCrossCheckError("official ContractGraph replay failed") from exc
    projection: dict[str, list[str]] = {}
    for graph_field in fields(graph):
        if graph_field.name == "component_lock_path":
            continue
        fingerprints: list[str] = []
        for value in getattr(graph, graph_field.name):
            fingerprint = getattr(value, "fingerprint", None)
            if not isinstance(fingerprint, str):
                to_dict = getattr(value, "to_dict", None)
                if not callable(to_dict):
                    raise FutuCrossCheckError(
                        f"ContractGraph collection {graph_field.name} is not receiptable"
                    )
                fingerprint = canonical_sha256(to_dict())
            _require_sha256(fingerprint, f"{graph_field.name} fingerprint")
            fingerprints.append(fingerprint)
        projection[graph_field.name] = fingerprints
    return canonical_sha256(projection)


def _premarket_contract_graph_fingerprint(graph: ContractGraph) -> str:
    """Derive the validated identity of an acyclic pre-market evidence graph."""

    if type(graph) is not ContractGraph:
        raise FutuCrossCheckError("pre-market ContractGraph type is not component-owned")
    if graph.market_reference_snapshots or graph.market_reference_validation_contexts:
        raise FutuCrossCheckError(
            "pre-market ContractGraph cannot retain market snapshots or contexts"
        )
    return contract_graph_fingerprint(graph)


def crosscheck_vendor_observation(
    *,
    graph: ContractGraph,
    official: OfficialEvidenceOperand,
    vendor: FutuObservation,
    created_at: str,
) -> FutuCrossCheckReceipt:
    """Compare a vendor-secondary value while leaving the SEC/IR object untouched."""
    graph_fingerprint = contract_graph_fingerprint(graph)
    return _crosscheck_vendor_observation_with_graph_fingerprint(
        graph=graph,
        graph_fingerprint=graph_fingerprint,
        official=official,
        vendor=vendor,
        created_at=created_at,
    )


def _crosscheck_vendor_observation_with_graph_fingerprint(
    *,
    graph: ContractGraph,
    graph_fingerprint: str,
    official: OfficialEvidenceOperand,
    vendor: FutuObservation,
    created_at: str,
) -> FutuCrossCheckReceipt:
    """Cross-check after the caller strictly derived the exact graph identity."""

    _replay_official_evidence_operand_with_graph_fingerprint(
        graph=graph,
        operand=official,
        graph_fingerprint=graph_fingerprint,
    )
    if vendor.source_role != "vendor_secondary":
        raise FutuCrossCheckError("only vendor-secondary observations may cross-check SEC/IR facts")
    materiality = _materiality_for_concept(official.canonical_concept)
    split_comparable = (
        vendor.comparison_eligible
        and official.canonical_concept in _SPLIT_CONCEPTS
        and vendor.canonical_concept == official.canonical_concept
        and vendor.issuer_id == official.issuer_id
        and split_observation_matches_official_period(vendor, official.period)
        and official.value_type == "number"
        and official.unit == "ratio"
        and official.currency is None
        and vendor.value_type == "text"
        and vendor.unit == "split_ratio"
        and vendor.currency is None
    )
    comparable = split_comparable or (
        vendor.comparison_eligible
        and vendor.canonical_concept == official.canonical_concept
        and vendor.issuer_id == official.issuer_id
        and to_json_value(vendor.period) == to_json_value(official.period)
        and vendor.value_type == official.value_type
        and vendor.unit == official.unit
        and vendor.currency == official.currency
    )
    if not comparable:
        return _make_receipt(
            official=official,
            vendor=vendor,
            comparison_rule="not_comparable",
            result="not_comparable",
            materiality=materiality,
            status="not_applicable",
            resolution=None,
            reviewer_id=None,
            created_at=created_at,
        )
    if official.value is None or vendor.value is None:
        return _make_receipt(
            official=official,
            vendor=vendor,
            comparison_rule="not_comparable",
            result="unavailable",
            materiality=materiality,
            status="not_applicable",
            resolution=None,
            reviewer_id=None,
            created_at=created_at,
        )

    if split_comparable:
        assert isinstance(official.value, str)
        assert isinstance(vendor.value, str)
        try:
            numerator, denominator = vendor.value.split("/", 1)
            vendor_ratio = Fraction(int(numerator), int(denominator))
        except (ValueError, ZeroDivisionError) as exc:
            raise FutuCrossCheckError("vendor split ratio is invalid") from exc
        official_decimal = _decimal(official.value, "official split ratio")
        comparison_rule = (
            "exact_split_ratio"
            if to_json_value(vendor.period) == to_json_value(official.period)
            else "exact_split_ratio_us_announcement_only"
        )
        consistent = Decimal(vendor_ratio.numerator) == (
            official_decimal * Decimal(vendor_ratio.denominator)
        )
    elif official.value_type == "number":
        official_decimal = _decimal(str(official.value), "official value")
        vendor_decimal = _decimal(str(vendor.value), "vendor value")
        if official.reported_precision_decimal is None:
            comparison_rule = "exact_decimal"
            consistent = official_decimal == vendor_decimal
        else:
            comparison_rule = "reported_precision_interval"
            half_precision = _decimal(
                official.reported_precision_decimal,
                "reported precision",
            ) / Decimal(2)
            consistent = (
                official_decimal - half_precision
                <= vendor_decimal
                <= official_decimal + half_precision
            )
    else:
        comparison_rule = "exact_text"
        consistent = official.value == vendor.value

    return _make_receipt(
        official=official,
        vendor=vendor,
        comparison_rule=comparison_rule,
        result="consistent" if consistent else "conflict",
        materiality=materiality,
        status="resolved" if consistent else "review_required",
        resolution=None,
        reviewer_id=None,
        created_at=created_at,
    )


def resolve_crosscheck(
    receipt: FutuCrossCheckReceipt,
    *,
    reviewer_id: str,
    resolution: str,
) -> FutuCrossCheckReceipt:
    """Record review without authorizing a vendor overwrite or in-place official correction."""
    if not reviewer_id.startswith("human:") or len(reviewer_id) <= len("human:"):
        raise FutuCrossCheckError("cross-check resolution requires an identified human reviewer")
    if resolution not in _RESOLUTIONS:
        raise FutuCrossCheckError("cross-check resolution is outside the closed registry")
    if receipt.status not in {"review_required", "not_applicable"}:
        raise FutuCrossCheckError("only unresolved cross-checks can receive a review decision")
    values = receipt.to_dict()
    values.pop("receipt_id")
    values.pop("receipt_fingerprint")
    values["status"] = "resolved"
    values["resolution"] = resolution
    values["reviewer_id"] = reviewer_id
    receipt_id, fingerprint = content_identity(
        "futu-crosscheck:",
        values,
        object_id_field="receipt_id",
        fingerprint_field="receipt_fingerprint",
    )
    return FutuCrossCheckReceipt(
        receipt_id=receipt_id,
        receipt_fingerprint=fingerprint,
        **values,
    )


def bind_crosschecks_to_bundle(
    bundle: FutuEvidenceBundle,
    cross_checks: Sequence[FutuCrossCheckReceipt],
) -> FutuEvidenceBundle:
    """Create a new bundle identity that references reviews without mutating vendor or SEC data."""
    receipts = tuple(sorted(cross_checks, key=lambda item: item.receipt_id))
    vendor_references = {
        (item["object_id"], item["fingerprint"]) for item in bundle.observations
    }
    for receipt in receipts:
        if receipt.issuer_id != bundle.issuer_id:
            raise FutuCrossCheckError("cross-check issuer does not match the evidence bundle")
        if (
            receipt.vendor_observation_id,
            receipt.vendor_observation_fingerprint,
        ) not in vendor_references:
            raise FutuCrossCheckError("cross-check vendor observation is outside the bundle")
    existing = tuple(
        (item["object_id"], item["fingerprint"]) for item in bundle.cross_checks
    )
    incoming = tuple((item.receipt_id, item.fingerprint) for item in receipts)
    if existing and existing != incoming:
        raise FutuCrossCheckError("cross-check binding is immutable; create from the base bundle")
    values = bundle.to_dict()
    values.pop("bundle_id")
    values.pop("bundle_fingerprint")
    values["cross_checks"] = [
        {"object_id": item.receipt_id, "fingerprint": item.fingerprint}
        for item in receipts
    ]
    if any(item.status == "review_required" for item in receipts):
        values["status"] = "partial"
        values["issues"] = sorted(
            {*values["issues"], "vendor_conflict_review_required"}
        )
    bundle_id, fingerprint = content_identity(
        "futu-bundle:",
        values,
        object_id_field="bundle_id",
        fingerprint_field="bundle_fingerprint",
    )
    return FutuEvidenceBundle(
        bundle_id=bundle_id,
        bundle_fingerprint=fingerprint,
        **values,
    )


def _make_receipt(
    *,
    official: OfficialEvidenceOperand,
    vendor: FutuObservation,
    comparison_rule: str,
    result: str,
    materiality: str,
    status: str,
    resolution: str | None,
    reviewer_id: str | None,
    created_at: str,
) -> FutuCrossCheckReceipt:
    values: dict[str, Any] = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "issuer_id": official.issuer_id,
        "contract_graph_fingerprint": official.contract_graph_fingerprint,
        "official_operand_fingerprint": official.fingerprint,
        "official_object_type": official.object_type,
        "official_object_id": official.object_id,
        "official_object_fingerprint": official.object_fingerprint,
        "official_authority": official.authority,
        "vendor_observation_id": vendor.observation_id,
        "vendor_observation_fingerprint": vendor.fingerprint,
        "canonical_concept": official.canonical_concept,
        "comparison_rule": comparison_rule,
        "result": result,
        "materiality": materiality,
        "status": status,
        "resolution": resolution,
        "reviewer_id": reviewer_id,
        "vendor_may_overwrite": False,
        "created_at": created_at,
    }
    receipt_id, fingerprint = content_identity(
        "futu-crosscheck:",
        values,
        object_id_field="receipt_id",
        fingerprint_field="receipt_fingerprint",
    )
    try:
        return FutuCrossCheckReceipt(
            receipt_id=receipt_id,
            receipt_fingerprint=fingerprint,
            **values,
        )
    except FutuReceiptError as exc:
        raise FutuCrossCheckError(str(exc)) from exc


def _materiality_for_concept(canonical_concept: str) -> str:
    mappings: Mapping[str, FrozenMap] = load_financial_field_registry()
    for mapping in mappings.values():
        if mapping["canonical_concept"] == canonical_concept:
            return mapping["materiality_tier"]
    return "context_only"


def _require_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise FutuCrossCheckError(f"{label} must be a lowercase SHA-256 digest")


def _decimal(value: str, label: str) -> Decimal:
    if not isinstance(value, str) or _CANONICAL_DECIMAL.fullmatch(value) is None:
        raise FutuCrossCheckError(f"{label} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise FutuCrossCheckError(f"{label} must be a finite decimal string") from exc
    if not parsed.is_finite():
        raise FutuCrossCheckError(f"{label} must be finite")
    return parsed


def _graph_owned_object(
    graph: ContractGraph,
    supplied: Fact | Claim | SourceDocument,
) -> Fact | Claim | SourceDocument:
    if isinstance(supplied, Fact):
        collection: Sequence[Fact | Claim | SourceDocument] = graph.facts
        supplied_id = supplied.fact_id
    elif isinstance(supplied, Claim):
        collection = graph.claims
        supplied_id = supplied.claim_id
    elif isinstance(supplied, SourceDocument):
        collection = graph.documents
        supplied_id = supplied.document_id
    else:  # pragma: no cover - static type boundary
        raise FutuCrossCheckError("unsupported official evidence object")
    matches = [item for item in collection if _official_object_id(item) == supplied_id]
    if len(matches) != 1:
        raise FutuCrossCheckError("official evidence object is outside the ContractGraph")
    retained = matches[0]
    if retained.fingerprint != supplied.fingerprint or retained.to_dict() != supplied.to_dict():
        raise FutuCrossCheckError("official evidence object was rebound outside the graph")
    return retained


def _official_object_id(value: Fact | Claim | SourceDocument) -> str:
    if isinstance(value, Fact):
        return value.fact_id
    if isinstance(value, Claim):
        return value.claim_id
    return value.document_id


def _fact_value(fact: Fact) -> str | bool | None:
    if fact.value_type != "number":
        return fact.value  # type: ignore[return-value]
    decimal_value = _decimal(str(fact.value), "official Fact value")
    rendered = format(decimal_value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"
