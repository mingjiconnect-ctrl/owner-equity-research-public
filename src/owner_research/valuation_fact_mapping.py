"""Deterministic, price-blind mapping from research evidence to a kernel FactLedger.

Phase 5B reads the canonical ResearchBundle artifact pair and the matching complete
ContractGraph.  It never fetches evidence, accepts caller-selected Facts, imports kernel
code, writes valuation artifacts, or creates assumptions.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker

from .calculation_integrity import expected_input_fingerprint, expected_output_fingerprint
from .component_lock import file_sha256
from .contracts import CalculationResult, Fact, FiscalPeriod, SourceDocument
from .fingerprints import FrozenMap
from .research_bundle_artifacts import (
    ResearchBundleArtifactError,
    load_research_bundle_artifacts,
)
from .research_bundle_validation import dependency_closure
from .validation import ContractGraph, ContractGraphError
from .valuation_fact_mapping_policies import (
    MAPPING_POLICY_ID,
    MAPPING_POLICY_VERSION,
    PINNED_FACT_LEDGER_SCHEMA_SHA256,
    ConceptMappingPolicy,
    UnitMappingPolicy,
    calculation_policy,
    concept_policy,
    mapping_policy_sha256,
    source_policy,
    unit_policy,
)
from .valuation_fact_mapping_types import FactLedgerMappingResult, FactMappingDecision

KERNEL_COMMIT = "be9b0773d5a78f5f8a33ba982494512668df85fe"
KERNEL_TAG = "v2.0.0-rc.2"


class FactLedgerMappingError(ValueError):
    """Raised when a critical price-blind mapping invariant cannot be closed."""


@dataclass(frozen=True, slots=True)
class _RawCandidate:
    fact: Fact
    document: SourceDocument
    concept: ConceptMappingPolicy
    unit: UnitMappingPolicy
    kernel_fact: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Lineage:
    kernel_fact_id: str
    source_id: str
    confidence: str


def _git(repository: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repository), *args],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise FactLedgerMappingError("pinned kernel checkout cannot be verified") from exc


def _load_kernel_fact_schema(repository: Path) -> dict[str, Any]:
    kernel = Path(repository).expanduser().resolve()
    if _git(kernel, "rev-parse", "HEAD") != KERNEL_COMMIT:
        raise FactLedgerMappingError("kernel checkout is not at the pinned commit")
    if _git(kernel, "rev-parse", f"{KERNEL_TAG}^{{}}") != KERNEL_COMMIT:
        raise FactLedgerMappingError("kernel release tag does not resolve to the pinned commit")
    path = kernel / "schemas" / "fact-ledger.schema.json"
    if not path.is_file() or file_sha256(path) != PINNED_FACT_LEDGER_SCHEMA_SHA256:
        raise FactLedgerMappingError("pinned FactLedger Schema is missing or changed")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FactLedgerMappingError("pinned FactLedger Schema cannot be loaded") from exc


def _bundle_closure(graph: ContractGraph, bundle: Any) -> dict[str, tuple[str, Any]]:
    roots = tuple(
        object_id
        for reference in bundle.module_references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(graph, roots)
    if set(bundle.source_document_ids) != {
        identifier for identifier, (kind, _) in closure.items() if kind == "SourceDocument"
    }:
        raise FactLedgerMappingError("Bundle and ContractGraph source closure differ")
    return closure


def _source_is_registered(document: SourceDocument) -> bool:
    try:
        policy = source_policy(document.authority_level)
    except KeyError:
        return False
    if document.document_type not in policy.permitted_document_types:
        return False
    parsed = urlparse(document.source_url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    if document.authority_level == "primary_regulatory":
        host = parsed.hostname.lower()
        if host != "sec.gov" and not host.endswith(".sec.gov"):
            return False
    return True


def _source_ref(document: SourceDocument) -> dict[str, Any]:
    policy = source_policy(document.authority_level)
    values = {
        "issuer_id": document.issuer_id,
        "document_type": document.document_type,
        "published_date": document.published_date,
    }
    return {
        "source_id": document.document_id,
        "title": policy.title_template.format(**values),
        "publisher": policy.publisher_template.format(**values),
        "published_date": document.published_date,
        "retrieved_at": document.retrieved_at,
        "locator": (
            f"document_id={document.document_id};"
            f"content_sha256={document.content_sha256}"
        ),
        "url": document.source_url,
        "local_path": None,
        "primary": policy.primary,
    }


def _scaled_value(value: float | int, policy: UnitMappingPolicy) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FactLedgerMappingError("numeric Fact contains a nonnumeric value")
    if policy.multiplier is None:
        raise FactLedgerMappingError("unit policy has no deterministic scale")
    scaled = Decimal(str(value)) * Decimal(str(policy.multiplier))
    return int(scaled) if scaled == scaled.to_integral_value() else float(scaled)


def _period_payload(
    fact: Fact | CalculationResult,
    policy: ConceptMappingPolicy,
) -> dict[str, Any]:
    start = fact.period["start"]
    end = fact.period["end"]
    if end is None:
        raise FactLedgerMappingError("measurement period has no end date")
    if policy.period_kind == "stock":
        if start is not None:
            raise FactLedgerMappingError("stock Fact must use a point-in-time period")
        return {"as_of_date": end, "period_start": None, "period_end": end}
    if start is None or start > end:
        raise FactLedgerMappingError("flow Fact must use a complete ordered period")
    return {"as_of_date": end, "period_start": start, "period_end": end}


def _fact_candidate(
    fact: Fact,
    *,
    document: SourceDocument,
    issuer_id: str,
    cutoff: str,
    segment_fact_ids: set[str],
) -> tuple[_RawCandidate | None, tuple[str, ...], str]:
    if fact.issuer_id != issuer_id:
        return None, ("cross_issuer_evidence",), "blocked"
    if fact.value_type != "number" or isinstance(fact.value, bool):
        return None, ("fact_not_numeric",), "excluded"
    if fact.confidence == "low":
        return None, ("confidence_too_low",), "excluded"
    if fact.fact_id in segment_fact_ids:
        return None, ("segment_scope_not_supported",), "excluded"
    if fact.derivation is not None or fact.parent_fact_ids:
        return None, ("raw_derivation_not_allowed",), "excluded"
    if document.issuer_id != issuer_id:
        return None, ("cross_issuer_evidence",), "blocked"
    if document.published_date > cutoff:
        return None, ("future_evidence",), "blocked"
    if not _source_is_registered(document):
        return None, ("source_not_official",), "blocked"
    try:
        concept = concept_policy(fact.concept)
    except KeyError:
        return None, ("concept_not_registered",), "blocked"
    if "raw" not in concept.permitted_origins:
        return None, ("raw_derivation_not_allowed",), "excluded"
    try:
        unit = unit_policy(fact.unit or "")
    except KeyError:
        return None, ("unit_not_registered",), "blocked"
    if not unit.price_blind_eligible or unit.unit_family != concept.unit_family:
        return None, ("unit_semantics_mismatch",), "blocked"
    try:
        dates = _period_payload(fact, concept)
    except FactLedgerMappingError:
        return None, ("period_invalid",), "blocked"
    if dates["as_of_date"] > cutoff:
        return None, ("future_evidence",), "blocked"
    target_unit = unit.target_unit_template
    if target_unit is None:
        return None, ("unit_semantics_mismatch",), "blocked"
    if unit.unit_family == "currency":
        if fact.currency is None:
            return None, ("unit_semantics_mismatch",), "blocked"
        target_unit = target_unit.format(currency=fact.currency)
    else:
        target_unit = target_unit.format(currency="")
    kernel_fact = {
        "fact_id": fact.fact_id,
        "concept": concept.kernel_concept,
        "value": _scaled_value(fact.value, unit),
        "unit": target_unit,
        "category": concept.category,
        "source_id": document.document_id,
        "source_location": fact.source_locator,
        **dates,
        "currency": fact.currency,
        "confidence": fact.confidence,
        "raw": True,
        "parent_fact_ids": [],
        "derivation": None,
        "equity_bridge_role": None,
    }
    return _RawCandidate(fact, document, concept, unit, kernel_fact), (), "mapped"


def _candidate_key(candidate: _RawCandidate) -> tuple[str, str | None, str | None]:
    payload = candidate.kernel_fact
    return (payload["concept"], payload["period_start"], payload["period_end"])


def _select_current_candidates(
    candidates: list[_RawCandidate],
    *,
    authoritative_fact_ids: set[str],
) -> tuple[list[_RawCandidate], dict[str, FactMappingDecision]]:
    groups: dict[tuple[str, str | None, str | None], list[_RawCandidate]] = {}
    for candidate in candidates:
        groups.setdefault(_candidate_key(candidate), []).append(candidate)
    selected: list[_RawCandidate] = []
    decisions: dict[str, FactMappingDecision] = {}
    for group in groups.values():
        if len(group) == 1:
            selected.append(group[0])
            continue
        authorities = [item for item in group if item.fact.fact_id in authoritative_fact_ids]
        if len(authorities) == 1:
            winner = authorities[0]
            selected.append(winner)
            for item in group:
                if item is not winner:
                    decisions[item.fact.fact_id] = FactMappingDecision(
                        "Fact",
                        item.fact.fact_id,
                        "excluded",
                        ("superseded_by_authoritative_fact",),
                    )
            continue
        semantic_values = {
            (item.kernel_fact["value"], item.kernel_fact["unit"], item.fact.currency)
            for item in group
        }
        if len(semantic_values) == 1:
            winner = max(
                group,
                key=lambda item: (
                    item.document.document_type.endswith("/A"),
                    item.document.published_date,
                    item.fact.fact_id,
                ),
            )
            selected.append(winner)
            for item in group:
                if item is not winner:
                    decisions[item.fact.fact_id] = FactMappingDecision(
                        "Fact",
                        item.fact.fact_id,
                        "excluded",
                        ("duplicate_equivalent",),
                    )
            continue
        for item in group:
            decisions[item.fact.fact_id] = FactMappingDecision(
                "Fact",
                item.fact.fact_id,
                "blocked",
                ("conflicting_current_fact", "restatement_chain_unresolved"),
            )
    return selected, decisions


def _calculation_order(calculations: dict[str, CalculationResult]) -> tuple[str, ...]:
    order: list[str] = []
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visited:
            return
        visited.add(identifier)
        for parent in sorted(calculations[identifier].input_calculation_ids):
            if parent in calculations:
                visit(parent)
        order.append(identifier)

    for identifier in sorted(calculations):
        visit(identifier)
    return tuple(order)


def _derived_concept(
    calculation: CalculationResult,
) -> tuple[ConceptMappingPolicy, str] | None:
    try:
        policy = calculation_policy(
            calculation.calculator_id,
            calculation.calculator_version,
        )
    except KeyError:
        return None
    for suffix in policy.allowed_output_suffixes:
        if calculation.concept.endswith(suffix):
            base = calculation.concept.removesuffix(suffix)
            try:
                concept = concept_policy(base)
            except KeyError:
                return None
            if "derived" in concept.permitted_origins:
                return concept, suffix
    return None


def _derived_period_is_registered(
    calculation: CalculationResult,
    *,
    suffix: str,
    periods: dict[str, FiscalPeriod],
) -> bool:
    period = dict(calculation.period)
    eligible_periods = [
        periods[identifier]
        for identifier in calculation.input_period_ids
        if identifier in periods
    ]
    if suffix == ".single_quarter":
        return any(
            period == {"start": item.quarter_start, "end": item.quarter_end}
            for item in eligible_periods
        )
    if suffix == ".ttm":
        return any(
            period == {"start": item.ttm_start, "end": item.quarter_end}
            for item in eligible_periods
        )
    return False


def _mapped_unit(
    *,
    unit: str | None,
    currency: str | None,
    concept: ConceptMappingPolicy,
) -> tuple[UnitMappingPolicy, str] | None:
    try:
        policy = unit_policy(unit or "")
    except KeyError:
        return None
    if not policy.price_blind_eligible or policy.unit_family != concept.unit_family:
        return None
    target = policy.target_unit_template
    if target is None:
        return None
    if policy.unit_family == "currency":
        if currency is None:
            return None
        target = target.format(currency=currency)
    else:
        target = target.format(currency="")
    return policy, target


def _calculation_fingerprints_replay(
    calculation: CalculationResult,
    *,
    facts: dict[str, Fact],
    calculations: dict[str, CalculationResult],
    periods: dict[str, FiscalPeriod],
) -> bool:
    try:
        input_hash = expected_input_fingerprint(
            calculation,
            facts=facts,
            assumptions={},
            calculations=calculations,
            periods=periods,
        )
    except KeyError:
        return False
    return (
        calculation.input_fingerprint == input_hash
        and calculation.output_fingerprint == expected_output_fingerprint(calculation)
    )


def _map_derived_calculations(
    *,
    closure: dict[str, tuple[str, Any]],
    raw_candidates: list[_RawCandidate],
    fact_decisions: dict[str, FactMappingDecision],
    reporting_currency: str,
    cutoff: str,
) -> tuple[list[dict[str, Any]], list[FactMappingDecision]]:
    calculations = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "CalculationResult"
    }
    facts = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "Fact"
    }
    periods = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "FiscalPeriod"
    }
    lineages: dict[str, _Lineage] = {
        item.fact.fact_id: _Lineage(
            kernel_fact_id=item.fact.fact_id,
            source_id=item.document.document_id,
            confidence=item.fact.confidence,
        )
        for item in raw_candidates
        if fact_decisions[item.fact.fact_id].disposition == "mapped"
    }
    existing_keys = {
        _candidate_key(item): item.kernel_fact
        for item in raw_candidates
        if item.fact.fact_id in lineages
    }
    derived: list[dict[str, Any]] = []
    decisions: dict[str, FactMappingDecision] = {}
    derived_keys: dict[tuple[str, str | None, str | None], dict[str, Any]] = {}
    for identifier in _calculation_order(calculations):
        calculation = calculations[identifier]
        output_id = f"derived:{identifier}"
        try:
            registered_calculator = calculation_policy(
                calculation.calculator_id,
                calculation.calculator_version,
            )
        except KeyError:
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "excluded",
                ("calculation_not_registered",),
            )
            continue
        if (
            calculation.generator != "deterministic_program"
            or calculation.code_sha256 != registered_calculator.code_sha256
        ):
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "blocked",
                ("calculation_fingerprint_mismatch",),
            )
            continue
        if calculation.input_assumption_ids:
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "blocked",
                ("calculation_uses_assumption",),
            )
            continue
        registered_output = _derived_concept(calculation)
        if registered_output is None:
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "excluded",
                ("concept_not_registered",),
            )
            continue
        concept, suffix = registered_output
        if not _calculation_fingerprints_replay(
            calculation,
            facts=facts,
            calculations=calculations,
            periods=periods,
        ):
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "blocked",
                ("calculation_fingerprint_mismatch",),
            )
            continue
        parent_ids = (*calculation.input_fact_ids, *calculation.input_calculation_ids)
        if not parent_ids or any(parent not in lineages for parent in parent_ids):
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "blocked",
                ("lineage_incomplete",),
            )
            continue
        parent_lineage = [lineages[parent] for parent in parent_ids]
        source_ids = {item.source_id for item in parent_lineage}
        if len(source_ids) != 1:
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "blocked",
                ("calculation_source_ambiguous",),
            )
            continue
        unit_mapping = _mapped_unit(
            unit=calculation.unit,
            currency=calculation.currency,
            concept=concept,
        )
        if unit_mapping is None:
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "blocked",
                ("unit_semantics_mismatch",),
            )
            continue
        unit, target_unit = unit_mapping
        if unit.unit_family == "currency" and calculation.currency != reporting_currency:
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "blocked",
                ("currency_mismatch",),
            )
            continue
        try:
            dates = _period_payload(calculation, concept)
        except FactLedgerMappingError:
            decisions[identifier] = FactMappingDecision(
                "CalculationResult", identifier, "blocked", ("period_invalid",)
            )
            continue
        if dates["as_of_date"] > cutoff or not _derived_period_is_registered(
            calculation,
            suffix=suffix,
            periods=periods,
        ):
            decisions[identifier] = FactMappingDecision(
                "CalculationResult", identifier, "blocked", ("period_invalid",)
            )
            continue
        confidence = (
            "medium" if any(item.confidence == "medium" for item in parent_lineage) else "high"
        )
        kernel_fact = {
            "fact_id": output_id,
            "concept": concept.kernel_concept,
            "value": _scaled_value(calculation.value, unit),
            "unit": target_unit,
            "category": concept.category,
            "source_id": next(iter(source_ids)),
            "source_location": (
                f"calculation_id={identifier};"
                f"output_fingerprint={calculation.output_fingerprint}"
            ),
            **dates,
            "currency": calculation.currency,
            "confidence": confidence,
            "raw": False,
            "parent_fact_ids": sorted(item.kernel_fact_id for item in parent_lineage),
            "derivation": (
                f"{calculation.calculator_id}@{calculation.calculator_version}:"
                f"{suffix.removeprefix('.')}"
            ),
            "equity_bridge_role": None,
        }
        key = (kernel_fact["concept"], kernel_fact["period_start"], kernel_fact["period_end"])
        existing = existing_keys.get(key)
        if existing is not None:
            identical = all(
                existing[field] == kernel_fact[field]
                for field in ("value", "unit", "currency")
            )
            decisions[identifier] = FactMappingDecision(
                "CalculationResult",
                identifier,
                "excluded" if identical else "blocked",
                (("duplicate_equivalent",) if identical else ("conflicting_current_fact",)),
            )
            continue
        if key in derived_keys:
            raise FactLedgerMappingError("multiple derived calculations claim one current series")
        derived_keys[key] = kernel_fact
        derived.append(kernel_fact)
        lineages[identifier] = _Lineage(output_id, next(iter(source_ids)), confidence)
        decisions[identifier] = FactMappingDecision(
            "CalculationResult", identifier, "mapped", (), output_id
        )
    return derived, list(decisions.values())


def _validate_ledger(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        message = "; ".join(error.message for error in errors[:3])
        raise FactLedgerMappingError(f"compiled FactLedger violates pinned Schema: {message}")


def compile_price_blind_fact_ledger(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
) -> FactLedgerMappingResult:
    """Compile official raw research Facts into a canonical price-blind FactLedger."""

    schema = _load_kernel_fact_schema(Path(kernel_repository))
    try:
        graph.validate()
        artifacts = load_research_bundle_artifacts(
            Path(bundle_artifact_directory),
            graph=graph,
        )
    except (ContractGraphError, ResearchBundleArtifactError) as exc:
        raise FactLedgerMappingError("Bundle artifacts and ContractGraph do not replay") from exc
    bundle = artifacts.bundle
    closure = _bundle_closure(graph, bundle)
    documents = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "SourceDocument"
    }
    segment_fact_ids = {
        assignment["fact_id"]
        for _, (kind, item) in closure.items()
        if kind == "SegmentSnapshot"
        for assignment in item.metric_assignments
    }
    authoritative_fact_ids = {
        item.authoritative_fact_id
        for _, (kind, item) in closure.items()
        if kind == "QuarterlyReconciliation" and item.authoritative_fact_id is not None
    }
    fact_decisions: dict[str, FactMappingDecision] = {}
    candidates: list[_RawCandidate] = []
    for identifier, (kind, item) in sorted(closure.items()):
        if kind != "Fact":
            continue
        document = documents.get(item.source_document_id)
        if document is None:
            fact_decisions[identifier] = FactMappingDecision(
                "Fact", identifier, "blocked", ("source_identity_incomplete",)
            )
            continue
        candidate, reasons, disposition = _fact_candidate(
            item,
            document=document,
            issuer_id=bundle.issuer_id,
            cutoff=bundle.data_cutoff_date,
            segment_fact_ids=segment_fact_ids,
        )
        if candidate is None:
            fact_decisions[identifier] = FactMappingDecision(
                "Fact", identifier, disposition, reasons
            )
        else:
            candidates.append(candidate)
    selected, conflict_decisions = _select_current_candidates(
        candidates,
        authoritative_fact_ids=authoritative_fact_ids,
    )
    fact_decisions.update(conflict_decisions)
    selected = [item for item in selected if item.fact.fact_id not in fact_decisions]
    currencies = {
        item.fact.currency
        for item in selected
        if item.unit.unit_family == "currency" and item.fact.currency is not None
    }
    if len(currencies) != 1:
        raise FactLedgerMappingError("reporting currency cannot be resolved uniquely")
    reporting_currency = next(iter(currencies))
    foreign = [item for item in selected if item.fact.currency not in {None, reporting_currency}]
    if foreign:
        raise FactLedgerMappingError("cross-currency raw Facts cannot enter kernel rc.1")
    mapped_fact_ids = {item.fact.fact_id for item in selected}
    for item in selected:
        fact_decisions[item.fact.fact_id] = FactMappingDecision(
            "Fact", item.fact.fact_id, "mapped", (), item.fact.fact_id
        )
    derived_facts, calculation_decisions = _map_derived_calculations(
        closure=closure,
        raw_candidates=selected,
        fact_decisions=fact_decisions,
        reporting_currency=reporting_currency,
        cutoff=bundle.data_cutoff_date,
    )
    used_document_ids = {item.document.document_id for item in selected}
    decisions: list[FactMappingDecision] = [
        *fact_decisions.values(),
        *calculation_decisions,
    ]
    for identifier, document in sorted(documents.items()):
        if identifier in used_document_ids:
            decisions.append(
                FactMappingDecision("SourceDocument", identifier, "mapped", (), identifier)
            )
        elif _source_is_registered(document):
            decisions.append(
                FactMappingDecision(
                    "SourceDocument",
                    identifier,
                    "excluded",
                    ("source_unused_by_mapped_fact",),
                )
            )
        else:
            decisions.append(
                FactMappingDecision(
                    "SourceDocument", identifier, "excluded", ("source_not_official",)
                )
            )
    if not mapped_fact_ids:
        raise FactLedgerMappingError("no eligible raw Fact remains after deterministic mapping")
    payload = {
        "schema_version": "1.0.0",
        "entity_id": bundle.issuer_id,
        "valuation_date": bundle.data_cutoff_date,
        "reporting_currency": reporting_currency,
        "sources": sorted(
            (_source_ref(documents[identifier]) for identifier in used_document_ids),
            key=lambda item: item["source_id"],
        ),
        "facts": sorted(
            (*[item.kernel_fact for item in selected], *derived_facts),
            key=lambda item: item["fact_id"],
        ),
    }
    _validate_ledger(payload, schema)
    if bundle.component_lock_sha256 != file_sha256(graph.component_lock_path):
        raise FactLedgerMappingError("Bundle component lock no longer matches the graph")
    return FactLedgerMappingResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        dependency_closure_sha256=bundle.dependency_closure_sha256,
        component_lock_sha256=bundle.component_lock_sha256,
        mapping_policy_id=MAPPING_POLICY_ID,
        mapping_policy_version=MAPPING_POLICY_VERSION,
        mapping_policy_sha256=mapping_policy_sha256(),
        kernel_fact_ledger_schema_sha256=PINNED_FACT_LEDGER_SCHEMA_SHA256,
        ledger_payload=FrozenMap(payload),
        decisions=tuple(decisions),
    )
