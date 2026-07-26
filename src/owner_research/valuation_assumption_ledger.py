"""Internal Phase 5D-2 named-human review and AssumptionLedger compiler."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .component_lock import file_sha256
from .contracts import ValuationAssumptionReviewDecision
from .fingerprints import canonical_sha256, to_json_value
from .research_bundle_artifacts import (
    ResearchBundleArtifactError,
    load_research_bundle_artifacts,
)
from .validation import ContractGraph, ContractGraphError
from .valuation_assumption_types import (
    AssumptionCandidateCompilationResult,
    AssumptionLedgerCompilationResult,
    AssumptionReviewRequest,
    PriceBlindReferenceClosure,
)
from .valuation_fact_mapping_policies import unit_policy
from .valuation_handoff_policies import (
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_TAG,
    assumption_evidence_policy_sha256,
    assumption_slot_policy,
    assumption_slot_policy_sha256,
    empty_supplemental_reference_closure_sha256,
)
from .valuation_phase5c_readiness import assess_phase5c_readiness

KERNEL_ASSUMPTION_SCHEMA_SHA256 = (
    "2232642332dc6444c784e21746cbd16bf8d4cd74fc483a0a345d95f98fc97a7a"
)


class AssumptionLedgerCompilationError(ValueError):
    """Raised when human review or kernel-assumption lineage cannot be replayed."""


def _git(repository: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repository), *args],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise AssumptionLedgerCompilationError(
            "pinned kernel checkout cannot be verified"
        ) from exc


def _load_assumption_schema(kernel_repository: Path) -> dict[str, Any]:
    kernel = Path(kernel_repository).expanduser().resolve()
    if _git(kernel, "rev-parse", "HEAD") != PINNED_KERNEL_COMMIT:
        raise AssumptionLedgerCompilationError("kernel checkout is not at the pinned commit")
    if _git(kernel, "rev-parse", f"{PINNED_KERNEL_TAG}^{{}}") != PINNED_KERNEL_COMMIT:
        raise AssumptionLedgerCompilationError(
            "kernel release tag does not resolve to the pinned commit"
        )
    path = kernel / "schemas" / "assumption-ledger.schema.json"
    if not path.is_file() or file_sha256(path) != KERNEL_ASSUMPTION_SCHEMA_SHA256:
        raise AssumptionLedgerCompilationError(
            "pinned AssumptionLedger Schema is missing or changed"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _decision_id(candidate: Any, request: AssumptionReviewRequest) -> str:
    return (
        f"valuation-assumption-decision:{candidate.issuer_id}:"
        f"{canonical_sha256(request.to_dict())[:20]}"
    )


def _reserved_assumption_id(candidate: Any) -> str:
    digest = canonical_sha256(
        {
            "issuer_id": candidate.issuer_id,
            "assumption_slot_id": candidate.assumption_slot_id,
            "candidate_fingerprint": candidate.fingerprint,
        }
    )
    return f"assumption:{candidate.issuer_id}:{digest[:20]}"


def _resolve_decisions(
    *,
    graph: ContractGraph,
    candidates: tuple[Any, ...],
    review_requests: tuple[AssumptionReviewRequest, ...],
    prior_decisions: tuple[ValuationAssumptionReviewDecision, ...],
) -> tuple[ValuationAssumptionReviewDecision, ...]:
    candidate_index = {item.candidate_id: item for item in candidates}
    if len(candidate_index) != len(candidates):
        raise AssumptionLedgerCompilationError("Candidate set repeats an ID")
    if len({item.candidate_id for item in review_requests}) != len(review_requests):
        raise AssumptionLedgerCompilationError(
            "one review compilation may decide each Candidate only once"
        )
    decisions = list(prior_decisions)
    prior_ids = {item.decision_id for item in prior_decisions}
    for request in sorted(review_requests, key=lambda item: item.candidate_id):
        candidate = candidate_index.get(request.candidate_id)
        if candidate is None:
            raise AssumptionLedgerCompilationError("review has a dangling Candidate")
        if (
            request.candidate_fingerprint != candidate.fingerprint
            or request.evidence_graph_sha256 != candidate.evidence_graph_sha256
        ):
            raise AssumptionLedgerCompilationError(
                "human review does not bind the exact Candidate and evidence graph"
            )
        if request.decision == "superseded" and request.supersedes_decision_id not in prior_ids:
            raise AssumptionLedgerCompilationError(
                "Decision supersession predecessor is unavailable"
            )
        decisions.append(
            ValuationAssumptionReviewDecision(
                schema_version="1.0.0",
                decision_id=_decision_id(candidate, request),
                issuer_id=candidate.issuer_id,
                candidate_id=candidate.candidate_id,
                candidate_fingerprint=candidate.fingerprint,
                evidence_graph_sha256=candidate.evidence_graph_sha256,
                decision=request.decision,
                reserved_kernel_assumption_id=(
                    _reserved_assumption_id(candidate)
                    if request.decision == "confirmed"
                    else None
                ),
                supersedes_decision_id=request.supersedes_decision_id,
                reviewer_type="human",
                reviewer_id=request.reviewer_id,
                reviewed_at=request.reviewed_at,
                rationale=request.rationale.strip(),
                issues=request.issues,
            )
        )
    replay = replace(
        graph,
        valuation_assumption_candidates=candidates,
        valuation_assumption_review_decisions=tuple(decisions),
    )
    try:
        replay.validate()
    except ContractGraphError as exc:
        raise AssumptionLedgerCompilationError(
            "human Decisions do not replay in the ContractGraph"
        ) from exc
    return tuple(sorted(decisions, key=lambda item: item.decision_id))


def _scaled_value(value: float | int, multiplier: float) -> float | int:
    scaled = Decimal(str(value)) * Decimal(str(multiplier))
    return int(scaled) if scaled == scaled.to_integral_value() else float(scaled)


def _supplemental_fact_id(closure: PriceBlindReferenceClosure, fact_id: str) -> str:
    return f"supplemental:{closure.fingerprint[:12]}:{fact_id}"


def _augment_fact_ledger(
    *,
    ledger_payload: dict[str, Any],
    closure: PriceBlindReferenceClosure | None,
    supplemental_fact_ids: set[str],
) -> tuple[dict[str, Any], dict[str, str]]:
    if not supplemental_fact_ids:
        return ledger_payload, {}
    if closure is None:
        raise AssumptionLedgerCompilationError(
            "confirmed assumptions cite an unavailable supplemental closure"
        )
    facts = {item.fact_id: item for item in closure.facts}
    documents = {item.document_id: item for item in closure.documents}
    mapped_ids: dict[str, str] = {}
    sources = list(ledger_payload["sources"])
    kernel_facts = list(ledger_payload["facts"])
    added_sources: set[str] = set()
    for fact_id in sorted(supplemental_fact_ids):
        fact = facts.get(fact_id)
        if fact is None:
            raise AssumptionLedgerCompilationError("supplemental assumption Fact is unavailable")
        document = documents[fact.source_document_id]
        try:
            policy = unit_policy(fact.unit or "")
        except KeyError as exc:
            raise AssumptionLedgerCompilationError(
                "supplemental assumption Fact has an unregistered unit"
            ) from exc
        if not policy.price_blind_eligible or policy.target_unit_template is None:
            raise AssumptionLedgerCompilationError(
                "supplemental assumption Fact unit is not price-blind eligible"
            )
        target_unit = policy.target_unit_template.format(currency=fact.currency or "")
        if policy.unit_family == "currency":
            if fact.currency != ledger_payload["reporting_currency"]:
                raise AssumptionLedgerCompilationError(
                    "supplemental monetary Fact does not match reporting currency"
                )
        elif fact.currency is not None:
            raise AssumptionLedgerCompilationError(
                "nonmonetary supplemental Fact cannot carry currency"
            )
        source_id = f"supplemental:{document.document_id}"
        if source_id not in added_sources:
            sources.append(
                {
                    "source_id": source_id,
                    "title": (
                        f"Price-blind {document.authority_level} evidence "
                        f"({document.document_type})"
                    ),
                    "publisher": document.issuer_id,
                    "published_date": document.published_date,
                    "retrieved_at": document.retrieved_at,
                    "locator": (
                        f"document_id={document.document_id};"
                        f"content_sha256={document.content_sha256}"
                    ),
                    "url": document.source_url,
                    "local_path": None,
                    "primary": document.authority_level in {
                        "primary_regulatory",
                        "company_primary",
                    },
                }
            )
            added_sources.add(source_id)
        mapped_id = _supplemental_fact_id(closure, fact.fact_id)
        mapped_ids[fact.fact_id] = mapped_id
        kernel_facts.append(
            {
                "fact_id": mapped_id,
                "concept": f"price_blind_evidence:{fact.concept}",
                "value": _scaled_value(fact.value, policy.multiplier or 0.0),
                "unit": target_unit,
                "category": "evidence",
                "source_id": source_id,
                "source_location": fact.source_locator,
                "as_of_date": fact.period["end"],
                "currency": fact.currency,
                "period_start": fact.period["start"],
                "period_end": fact.period["end"],
                "confidence": fact.confidence,
                "raw": True,
                "parent_fact_ids": [],
                "derivation": None,
                "equity_bridge_role": None,
            }
        )
    return (
        {
            **ledger_payload,
            "sources": sorted(sources, key=lambda item: item["source_id"]),
            "facts": sorted(kernel_facts, key=lambda item: item["fact_id"]),
        },
        mapped_ids,
    )


def _kernel_unit(candidate: Any, reporting_currency: str) -> tuple[float | int, str]:
    try:
        policy = unit_policy(candidate.unit)
    except KeyError as exc:
        raise AssumptionLedgerCompilationError(
            "Candidate unit is not registered for kernel assumptions"
        ) from exc
    if not policy.price_blind_eligible or policy.target_unit_template is None:
        raise AssumptionLedgerCompilationError(
            "Candidate unit cannot enter a price-blind kernel assumption"
        )
    if policy.unit_family == "currency":
        if candidate.currency != reporting_currency:
            raise AssumptionLedgerCompilationError(
                "Candidate currency does not match the price-blind FactLedger"
            )
    elif candidate.currency is not None:
        raise AssumptionLedgerCompilationError(
            "nonmonetary Candidate cannot carry currency"
        )
    return (
        _scaled_value(candidate.value, policy.multiplier or 0.0),
        policy.target_unit_template.format(currency=candidate.currency or ""),
    )


def _source_fact_ids(
    *,
    candidate: Any,
    ledger_fact_ids: set[str],
    supplemental_mapped_ids: dict[str, str],
) -> tuple[str, ...]:
    source_ids: set[str] = set()
    for binding in candidate.evidence_bindings:
        if binding["role"] != "support" or binding["contract_type"] not in {
            "Fact",
            "CalculationResult",
        }:
            continue
        if binding["evidence_domain"] == "supplemental_price_blind":
            mapped_id = supplemental_mapped_ids.get(binding["object_id"])
        else:
            mapped_id = (
                f"derived:{binding['object_id']}"
                if binding["contract_type"] == "CalculationResult"
                else binding["object_id"]
            )
        if mapped_id is None or mapped_id not in ledger_fact_ids:
            raise AssumptionLedgerCompilationError(
                "confirmed Candidate support does not map to the augmented FactLedger"
            )
        source_ids.add(mapped_id)
    if not source_ids:
        raise AssumptionLedgerCompilationError(
            "confirmed Candidate has no kernel-compatible source Fact"
        )
    return tuple(sorted(source_ids))


def _kernel_compatibility_validate(
    *,
    kernel_repository: Path,
    fact_ledger_payload: dict[str, Any],
    assumption_ledger_payload: dict[str, Any],
) -> None:
    schema = _load_assumption_schema(kernel_repository)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            assumption_ledger_payload
        ),
        key=lambda item: list(item.path),
    )
    if errors:
        raise AssumptionLedgerCompilationError(
            f"pinned AssumptionLedger Schema rejected the payload: {errors[0].message}"
        )
    script = r"""
import json
import sys
from owner_valuation import AssumptionLedger, FactLedger

payload = json.load(sys.stdin)
facts = FactLedger.from_dict(payload["fact_ledger"])
assumptions = AssumptionLedger.from_dict(payload["assumption_ledger"], facts)
json.dump(
    {"fact_fingerprint": facts.fingerprint, "assumption_ledger": assumptions.to_dict()},
    sys.stdout,
    sort_keys=True,
)
"""
    env = os.environ.copy()
    kernel_src = str(Path(kernel_repository).resolve() / "src")
    env["PYTHONPATH"] = kernel_src + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(
                {
                    "fact_ledger": fact_ledger_payload,
                    "assumption_ledger": assumption_ledger_payload,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        replay = json.loads(completed.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise AssumptionLedgerCompilationError(
            "pinned kernel AssumptionLedger validation failed"
        ) from exc
    if replay["assumption_ledger"] != assumption_ledger_payload:
        raise AssumptionLedgerCompilationError(
            "pinned kernel changed the canonical assumption entries"
        )


def _compile_with_readiness(
    *,
    graph: ContractGraph,
    bundle: Any,
    readiness: Any,
    kernel_repository: Path,
    candidate_result: AssumptionCandidateCompilationResult,
    review_requests: tuple[AssumptionReviewRequest, ...],
    supplemental_reference_closure: PriceBlindReferenceClosure | None,
    prior_decisions: tuple[ValuationAssumptionReviewDecision, ...] = (),
) -> AssumptionLedgerCompilationResult:
    if any(
        (
            graph.valuation_assumption_candidates,
            graph.valuation_assumption_review_decisions,
            graph.market_reference_snapshots,
            graph.valuation_handoffs,
        )
    ):
        raise AssumptionLedgerCompilationError(
            "AssumptionLedger compilation requires an unanchored Phase 5D graph"
        )
    closure_hash = (
        supplemental_reference_closure.fingerprint
        if supplemental_reference_closure is not None
        else empty_supplemental_reference_closure_sha256()
    )
    expected = {
        "issuer_id": bundle.issuer_id,
        "data_cutoff_date": bundle.data_cutoff_date,
        "research_bundle_id": bundle.bundle_id,
        "research_bundle_fingerprint": bundle.bundle_fingerprint,
        "research_bundle_dependency_sha256": bundle.dependency_closure_sha256,
        "phase5c_readiness_fingerprint": readiness.fingerprint,
        "supplemental_reference_closure_sha256": closure_hash,
        "assumption_slot_policy_sha256": assumption_slot_policy_sha256(),
        "assumption_evidence_policy_sha256": assumption_evidence_policy_sha256(),
    }
    actual = {
        key: getattr(candidate_result, key)
        for key in expected
    }
    if actual != expected:
        raise AssumptionLedgerCompilationError(
            "Candidate compilation does not replay the current price-blind context"
        )
    bound_graph = replace(
        graph,
        price_blind_reference_closures=(
            (supplemental_reference_closure,)
            if supplemental_reference_closure is not None
            else ()
        ),
    )
    candidate_graph = replace(
        bound_graph,
        valuation_assumption_candidates=candidate_result.candidates,
    )
    try:
        candidate_graph.validate()
    except ContractGraphError as exc:
        raise AssumptionLedgerCompilationError(
            "Candidate compilation no longer validates against the current graph"
        ) from exc
    decisions = _resolve_decisions(
        graph=bound_graph,
        candidates=candidate_result.candidates,
        review_requests=review_requests,
        prior_decisions=prior_decisions,
    )
    superseded = {
        item.supersedes_decision_id
        for item in decisions
        if item.supersedes_decision_id is not None
    }
    active_confirmed = tuple(
        item
        for item in decisions
        if item.decision == "confirmed" and item.decision_id not in superseded
    )
    candidates = {item.candidate_id: item for item in candidate_result.candidates}
    supplemental_ids = {
        binding["object_id"]
        for decision in active_confirmed
        for binding in candidates[decision.candidate_id].evidence_bindings
        if binding["role"] == "support"
        and binding["evidence_domain"] == "supplemental_price_blind"
        and binding["contract_type"] == "Fact"
    }
    ledger_payload = to_json_value(readiness.equity_bridge_result.ledger_payload)
    augmented, supplemental_mapped = _augment_fact_ledger(
        ledger_payload=ledger_payload,
        closure=supplemental_reference_closure,
        supplemental_fact_ids=supplemental_ids,
    )
    ledger_fact_ids = {item["fact_id"] for item in augmented["facts"]}
    assumptions: list[dict[str, Any]] = []
    for decision in sorted(active_confirmed, key=lambda item: item.reserved_kernel_assumption_id):
        candidate = candidates[decision.candidate_id]
        assumption_slot_policy(candidate.assumption_slot_id)
        value, unit = _kernel_unit(candidate, augmented["reporting_currency"])
        assumptions.append(
            {
                "assumption_id": decision.reserved_kernel_assumption_id,
                "value": value,
                "unit": unit,
                "concept": candidate.kernel_concept,
                "scope": candidate.method_scope,
                "rationale": candidate.rationale,
                "source_fact_ids": list(
                    _source_fact_ids(
                        candidate=candidate,
                        ledger_fact_ids=ledger_fact_ids,
                        supplemental_mapped_ids=supplemental_mapped,
                    )
                ),
                "scenario": candidate.scenario,
            }
        )
    assumption_payload = {
        "schema_version": "1.0.0",
        "fact_ledger_fingerprint": canonical_sha256(augmented),
        "assumptions": assumptions,
    }
    _kernel_compatibility_validate(
        kernel_repository=Path(kernel_repository),
        fact_ledger_payload=augmented,
        assumption_ledger_payload=assumption_payload,
    )
    return AssumptionLedgerCompilationResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        research_bundle_dependency_sha256=bundle.dependency_closure_sha256,
        phase5c_readiness_fingerprint=readiness.fingerprint,
        candidate_compilation_fingerprint=candidate_result.fingerprint,
        supplemental_reference_closure_sha256=closure_hash,
        decisions=decisions,
        augmented_fact_ledger_payload=augmented,
        assumption_ledger_payload=assumption_payload,
        assumption_entries_sha256=canonical_sha256(assumptions),
        kernel_assumption_schema_sha256=KERNEL_ASSUMPTION_SCHEMA_SHA256,
    )


def compile_reviewed_assumption_ledger(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
    candidate_result: AssumptionCandidateCompilationResult,
    review_requests: tuple[AssumptionReviewRequest, ...],
    supplemental_reference_closure: PriceBlindReferenceClosure | None = None,
    prior_decisions: tuple[ValuationAssumptionReviewDecision, ...] = (),
) -> AssumptionLedgerCompilationResult:
    """Replay Phase 5C and compile only named-human-confirmed kernel assumptions."""

    try:
        graph.validate()
        artifacts = load_research_bundle_artifacts(
            Path(bundle_artifact_directory),
            graph=graph,
        )
    except (ContractGraphError, ResearchBundleArtifactError) as exc:
        raise AssumptionLedgerCompilationError(
            "Bundle artifacts and ContractGraph do not replay"
        ) from exc
    bound_graph = replace(
        graph,
        manifests=tuple(
            artifacts.run_manifest if item.run_id == artifacts.run_manifest.run_id else item
            for item in graph.manifests
        ),
        research_bundles=(artifacts.bundle,),
    )
    readiness = assess_phase5c_readiness(
        bundle_artifact_directory=Path(bundle_artifact_directory),
        graph=bound_graph,
        kernel_repository=Path(kernel_repository),
    )
    return _compile_with_readiness(
        graph=bound_graph,
        bundle=artifacts.bundle,
        readiness=readiness,
        kernel_repository=Path(kernel_repository),
        candidate_result=candidate_result,
        review_requests=tuple(review_requests),
        supplemental_reference_closure=supplemental_reference_closure,
        prior_decisions=tuple(prior_decisions),
    )


__all__ = ()
