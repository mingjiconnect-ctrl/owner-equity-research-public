"""Deterministic Phase 5C-1 accounting reformulation compiler.

The compiler consumes the canonical Phase 4 bundle artifacts and a complete
ContractGraph, replays Phase 5B, and emits only the accounting-reconciliation
predecessor.  It is intentionally internal: no package-root, CLI, Skill, writer,
market, assumption, request, result, or valuation-kernel execution surface is
provided here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import defaultdict
from dataclasses import replace
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Claim,
    Fact,
    SourceDocument,
)
from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .research_bundle_artifacts import (
    ResearchBundleArtifactError,
    load_research_bundle_artifacts,
)
from .research_bundle_validation import dependency_closure
from .units import UnitError, unit_spec
from .validation import ContractGraph, ContractGraphError
from .valuation_accounting_policies import (
    ACCOUNT_CONCEPT_POLICIES,
    ACCOUNTING_FORMULA_DERIVATIONS,
    ACCOUNTING_RECONCILIATION_RELATIVE_TOLERANCE,
    COMMON_EQUITY_ALIAS_DERIVATIONS,
    FORMULA_POLICIES,
    OWNER_TRANSACTION_CONCEPTS,
    PERIOD_ALIGNMENT_POLICIES,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
    phase5c_policy_sha256,
)
from .valuation_accounting_types import (
    AccountClassificationDecision,
    AccountingFactDecision,
    AccountingReconciliationResult,
    _economic_claim_key,
    _economic_claim_review_statement,
)
from .valuation_fact_mapping import (
    _load_kernel_fact_schema,
    _source_is_registered,
    _source_ref,
    _validate_ledger,
    compile_price_blind_fact_ledger,
)
from .valuation_readiness import assess_method_readiness


class AccountingReconciliationError(ValueError):
    """Raised when Phase 5C-1 evidence cannot close without inference."""


_RAW_INPUT_CONCEPTS = frozenset(
    {
        "total_equity",
        "comprehensive_income_attributable_to_common",
        *OWNER_TRANSACTION_CONCEPTS,
        *(
            concept
            for concept, policy in ACCOUNT_CONCEPT_POLICIES.items()
            if policy.period_kind == "stock"
            and (policy.account_role != "unresolved" or policy.classification_requires_review)
        ),
    }
)
_FORMULA_OUTPUT_CONCEPTS = frozenset(policy.output_concept for policy in FORMULA_POLICIES.values())
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
_PERIMETER_CONCEPTS = frozenset(
    {"noncontrolling_interest", "preferred_stock", "other_non_common_equity_claim"}
)


def _issuer_scope(issuer_id: str) -> dict[str, Any]:
    return {
        "scope_type": "issuer_wide",
        "segment_definition_ids": [],
        "business_unit": None,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }


def _account_classification_review_statement(
    *,
    issuer_id: str,
    fact_id: str,
    concept: str,
    account_role: str,
    measurement_end: str,
    perimeter_disposition: dict[str, str] | None,
) -> str:
    semantic_sha = canonical_sha256(
        {
            "policy_id": PHASE5C_POLICY_ID,
            "policy_version": PHASE5C_POLICY_VERSION,
            "issuer_id": issuer_id,
            "fact_id": fact_id,
            "concept": concept,
            "account_role": account_role,
            "measurement_end": measurement_end,
            "perimeter_disposition": perimeter_disposition,
        }
    )
    return f"Reviewed Phase 5C account classification {semantic_sha}."


def _formula_inclusion_review_statement(
    *,
    issuer_id: str,
    purpose: str,
    input_role: str,
    measurement_end: str,
    fact_ids: tuple[str, ...],
    support_fact_ids: tuple[str, ...],
    inclusion_status: str,
) -> str:
    semantic_sha = canonical_sha256(
        {
            "policy_id": PHASE5C_POLICY_ID,
            "policy_version": PHASE5C_POLICY_VERSION,
            "issuer_id": issuer_id,
            "purpose": purpose,
            "input_role": input_role,
            "measurement_end": measurement_end,
            "fact_ids": sorted(fact_ids),
            "support_fact_ids": sorted(support_fact_ids),
            "inclusion_status": inclusion_status,
        }
    )
    return f"Reviewed Phase 5C formula inclusion {semantic_sha}."


def _bundle_roots(bundle: Any) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                object_id
                for reference in bundle.module_references
                for object_id in reference["object_ids"]
            }
        )
    )


def _load_context(
    directory: Path,
    graph: ContractGraph,
) -> tuple[Any, Any, dict[str, tuple[str, Any]]]:
    try:
        graph.validate()
        artifacts = load_research_bundle_artifacts(directory, graph=graph)
    except (ContractGraphError, ResearchBundleArtifactError) as exc:
        raise AccountingReconciliationError(
            "Bundle artifacts and ContractGraph do not replay"
        ) from exc
    bundle = artifacts.bundle
    closure = dependency_closure(graph, _bundle_roots(bundle))
    return bundle, artifacts.run_manifest, closure


def _confirmed_claim_chain(
    *,
    closure: dict[str, tuple[str, Any]],
    issuer_id: str,
    cutoff: str,
    statement: str,
    supporting_fact_ids: tuple[str, ...],
) -> tuple[AnalyticalClaimCandidate, AnalyticalClaimReviewDecision, Claim] | None:
    expected_support = set(supporting_fact_ids)
    candidates = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "AnalyticalClaimCandidate"
        and item.issuer_id == issuer_id
        and item.proposed_statement == statement
    }
    decisions = {
        item.candidate_id: item
        for _, (kind, item) in closure.items()
        if kind == "AnalyticalClaimReviewDecision"
        and item.issuer_id == issuer_id
        and item.decision == "confirmed"
    }
    claims = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "Claim" and item.issuer_id == issuer_id
    }
    matches: list[tuple[AnalyticalClaimCandidate, AnalyticalClaimReviewDecision, Claim]] = []
    cutoff_day = date.fromisoformat(cutoff)
    for candidate_id, candidate in candidates.items():
        support = {
            binding["fact_id"]
            for binding in candidate.supporting_evidence_bindings
            if binding["fact_id"] is not None
        }
        decision = decisions.get(candidate_id)
        claim = claims.get(decision.output_claim_id or "") if decision else None
        if (
            decision is None
            or claim is None
            or support != expected_support
            or any(
                binding["calculation_result_id"] is not None
                or binding["context_observation_id"] is not None
                for binding in candidate.supporting_evidence_bindings
            )
            or candidate.scope != freeze(_issuer_scope(issuer_id))
            or candidate.claim_role != "support"
            or candidate.business_attribute_role is not None
            or candidate.business_component_type is not None
            or candidate.validation_status != "ready"
            or candidate.validation_issues
            or not candidate.counterevidence_search_note
            or not candidate.falsification_condition
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or not decision.reviewer_id.startswith("human:")
            or datetime.fromisoformat(decision.reviewed_at.replace("Z", "+00:00")).date()
            > cutoff_day
            or claim.statement != statement
            or claim.as_of_date != candidate.as_of_date
            or set(claim.supporting_fact_ids) != expected_support
            or claim.counterevidence_search_note != candidate.counterevidence_search_note
            or claim.falsification_condition != candidate.falsification_condition
            or date.fromisoformat(claim.as_of_date) > cutoff_day
        ):
            continue
        matches.append((candidate, decision, claim))
    if len(matches) > 1:
        raise AccountingReconciliationError(
            "multiple confirmed analytical reviews claim one accounting semantic"
        )
    return matches[0] if matches else None


def _research_fact_to_kernel(
    fact: Fact,
    document: SourceDocument,
    *,
    reporting_currency: str,
    cutoff: str,
) -> dict[str, Any]:
    if (
        fact.value_type != "number"
        or isinstance(fact.value, bool)
        or fact.confidence not in {"high", "medium"}
        or fact.derivation is not None
        or fact.parent_fact_ids
        or fact.period["end"] is None
        or fact.period["end"] > cutoff
        or document.published_date > cutoff
        or not _source_is_registered(document)
    ):
        raise AccountingReconciliationError(
            f"Fact {fact.fact_id} is not eligible official raw accounting evidence"
        )
    policy = ACCOUNT_CONCEPT_POLICIES.get(fact.concept)
    if policy is None or fact.concept not in _RAW_INPUT_CONCEPTS:
        raise AccountingReconciliationError(
            f"Fact {fact.fact_id} concept is not a Phase 5C-1 input"
        )
    try:
        spec = unit_spec(fact.unit or "")
    except UnitError as exc:
        raise AccountingReconciliationError(f"Fact {fact.fact_id} unit is not registered") from exc
    if spec.family != "monetary" or fact.currency != reporting_currency:
        raise AccountingReconciliationError(
            f"Fact {fact.fact_id} does not use reporting-currency monetary units"
        )
    if policy.period_kind == "stock" and fact.period["start"] is not None:
        raise AccountingReconciliationError(f"Fact {fact.fact_id} stock period is invalid")
    if policy.period_kind == "flow" and fact.period["start"] is None:
        raise AccountingReconciliationError(f"Fact {fact.fact_id} flow period is incomplete")
    amount = Decimal(str(fact.value)) * spec.scale / Decimal("1000000")
    value: int | float = int(amount) if amount == amount.to_integral_value() else float(amount)
    return {
        "fact_id": fact.fact_id,
        "concept": fact.concept,
        "value": value,
        "unit": f"{reporting_currency} millions",
        "category": policy.kernel_category,
        "source_id": document.document_id,
        "source_location": fact.source_locator,
        "as_of_date": fact.period["end"],
        "currency": reporting_currency,
        "period_start": fact.period["start"],
        "period_end": fact.period["end"],
        "confidence": fact.confidence,
        "raw": True,
        "parent_fact_ids": [],
        "derivation": None,
        "equity_bridge_role": None,
    }


def _unique_by_semantic_key(
    facts: list[dict[str, Any]],
) -> dict[tuple[str, Any, Any], dict[str, Any]]:
    grouped: dict[tuple[str, Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for fact in facts:
        grouped[(fact["concept"], fact["period_start"], fact["period_end"])].append(fact)
    selected: dict[tuple[str, Any, Any], dict[str, Any]] = {}
    for key, rows in grouped.items():
        if len(rows) != 1:
            raise AccountingReconciliationError(
                "current accounting evidence contains an unresolved same-period conflict"
            )
        selected[key] = rows[0]
    return selected


def _raw_roots(fact_id: str, ledger: dict[str, dict[str, Any]]) -> frozenset[str]:
    fact = ledger[fact_id]
    parents = tuple(fact.get("parent_fact_ids", ()))
    if not parents:
        return frozenset({fact_id})
    roots: set[str] = set()
    for parent_id in parents:
        roots.update(_raw_roots(parent_id, ledger))
    return frozenset(roots)


def _derive_fact(
    *,
    purpose: str,
    input_fact_ids: tuple[str, ...],
    ledger: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], str, tuple[str, ...], str]:
    policy = FORMULA_POLICIES[purpose]
    inputs = [ledger[fact_id] for fact_id in input_fact_ids]
    if not inputs:
        raise AccountingReconciliationError(f"{purpose} has no eligible input Facts")
    periods = {(item["period_start"], item["period_end"], item["as_of_date"]) for item in inputs}
    currencies = {item["currency"] for item in inputs}
    units = {item["unit"] for item in inputs}
    if len(periods) != 1 or len(currencies) != 1 or len(units) != 1:
        raise AccountingReconciliationError(f"{purpose} inputs differ in period or unit")
    value = 0.0
    for term in policy.terms:
        for fact_id in input_fact_ids:
            if ledger[fact_id]["concept"] in term.permitted_concepts:
                value += term.sign * float(ledger[fact_id]["value"])
    start, end, as_of = next(iter(periods))
    output_id = f"derived:phase5c:{purpose}:{end}"
    calculation_id = f"calculation:phase5c:{purpose}:{end}"
    roots = tuple(
        sorted({root for fact_id in input_fact_ids for root in _raw_roots(fact_id, ledger)})
    )
    confidence = min(
        (item["confidence"] for item in inputs), key=lambda item: _CONFIDENCE_ORDER[item]
    )
    output = {
        "fact_id": output_id,
        "concept": policy.output_concept,
        "value": int(value) if value.is_integer() else value,
        "unit": inputs[0]["unit"],
        "category": ACCOUNT_CONCEPT_POLICIES[policy.output_concept].kernel_category,
        "source_id": sorted(item["source_id"] for item in inputs)[0],
        "source_location": f"{purpose} deterministic Phase 5C-1 formula",
        "as_of_date": as_of,
        "currency": inputs[0]["currency"],
        "period_start": start,
        "period_end": end,
        "confidence": confidence,
        "raw": False,
        "parent_fact_ids": list(input_fact_ids),
        "derivation": ACCOUNTING_FORMULA_DERIVATIONS[purpose],
        "equity_bridge_role": None,
    }
    return (
        output,
        calculation_id,
        roots,
        ("dependent_inputs" if any(not item["raw"] for item in inputs) else "independent_inputs"),
    )


def _reviewed_classification(
    *,
    closure: dict[str, tuple[str, Any]],
    fact: dict[str, Any],
    issuer_id: str,
    cutoff: str,
) -> tuple[str, dict[str, str] | None, tuple[str, str]] | None:
    policy = ACCOUNT_CONCEPT_POLICIES[fact["concept"]]
    perimeters: tuple[dict[str, str] | None, ...]
    if fact["concept"] in _PERIMETER_CONCEPTS:
        values = ("included", "excluded")
        perimeters = tuple(
            {
                "total_equity": total_equity,
                "reported_liabilities": reported_liabilities,
                "financial_obligations": financial_obligations,
            }
            for total_equity in values
            for reported_liabilities in values
            for financial_obligations in values
        )
    else:
        perimeters = (None,)
    matches: list[tuple[str, dict[str, str] | None, tuple[str, str]]] = []
    for role in policy.classification_roles:
        for perimeter in perimeters:
            statement = _account_classification_review_statement(
                issuer_id=issuer_id,
                fact_id=fact["fact_id"],
                concept=fact["concept"],
                account_role=role,
                measurement_end=fact["period_end"],
                perimeter_disposition=perimeter,
            )
            chain = _confirmed_claim_chain(
                closure=closure,
                issuer_id=issuer_id,
                cutoff=cutoff,
                statement=statement,
                supporting_fact_ids=(fact["fact_id"],),
            )
            if chain:
                matches.append((role, perimeter, (chain[2].claim_id, chain[1].decision_id)))
    if len(matches) > 1:
        raise AccountingReconciliationError(
            f"Fact {fact['fact_id']} has conflicting reviewed account classifications"
        )
    return matches[0] if matches else None


def _account_decisions(
    *,
    ledger: dict[str, dict[str, Any]],
    measurement_end: str,
    closure: dict[str, tuple[str, Any]],
    issuer_id: str,
    cutoff: str,
) -> tuple[AccountClassificationDecision, ...]:
    candidates = [
        item
        for item in ledger.values()
        if item["raw"] is True
        and item["as_of_date"] == measurement_end
        and (policy := ACCOUNT_CONCEPT_POLICIES.get(item["concept"])) is not None
        and policy.period_kind == "stock"
        and (policy.account_role != "unresolved" or policy.classification_requires_review)
    ]
    prepared: list[tuple[dict[str, Any], str, dict[str, str] | None, tuple[str, str] | None]] = []
    for fact in candidates:
        policy = ACCOUNT_CONCEPT_POLICIES[fact["concept"]]
        if policy.classification_requires_review:
            reviewed = _reviewed_classification(
                closure=closure,
                fact=fact,
                issuer_id=issuer_id,
                cutoff=cutoff,
            )
            if reviewed is None:
                raise AccountingReconciliationError(
                    f"Fact {fact['fact_id']} requires a named-human reviewed classification"
                )
            role, perimeter, proof = reviewed
        else:
            role, perimeter, proof = policy.account_role, None, None
        prepared.append((fact, role, perimeter, proof))
    by_role: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fact, role, _, _ in prepared:
        by_role[role].append(fact)
    aggregate_concepts = {
        "operating_asset": "operating_assets",
        "operating_liability": "operating_liabilities",
        "financial_asset": "financial_assets",
        "financial_obligation": "financial_obligations",
    }
    for role, rows in by_role.items():
        if role not in aggregate_concepts:
            continue
        has_aggregate = any(item["concept"] == aggregate_concepts[role] for item in rows)
        if has_aggregate and len(rows) != 1:
            raise AccountingReconciliationError(
                f"{role} aggregate and components cannot be consumed together"
            )
    decisions: list[AccountClassificationDecision] = []
    for fact, role, perimeter, proof in prepared:
        aggregating = role in aggregate_concepts
        aggregate = aggregating and fact["concept"] == aggregate_concepts[role]
        decisions.append(
            AccountClassificationDecision(
                fact_id=fact["fact_id"],
                concept=fact["concept"],
                status="classified",
                account_role=role,
                classification_basis=("reviewed_claim" if proof else "registered_concept"),
                classification_claim_id=proof[0] if proof else None,
                review_decision_id=proof[1] if proof else None,
                aggregation_set_id=f"phase5c:{issuer_id}:{measurement_end}:{role}"
                if aggregating
                else None,
                aggregation_level=(
                    "aggregate" if aggregate else "component" if aggregating else "not_applicable"
                ),
                root_fact_ids=(fact["fact_id"],),
                reason_codes=(),
                rationale=(
                    "Named-human reviewed classification."
                    if proof
                    else "Closed registered account concept."
                ),
                perimeter_disposition=perimeter,
            )
        )
    return tuple(sorted(decisions, key=lambda item: item.fact_id))


def _formula_inclusion_proof(
    *,
    closure: dict[str, tuple[str, Any]],
    issuer_id: str,
    cutoff: str,
    purpose: str,
    input_role: str,
    measurement_end: str,
    fact_ids: tuple[str, ...],
    support_fact_ids: tuple[str, ...],
    inclusion_status: str,
) -> tuple[str, str]:
    statement = _formula_inclusion_review_statement(
        issuer_id=issuer_id,
        purpose=purpose,
        input_role=input_role,
        measurement_end=measurement_end,
        fact_ids=fact_ids,
        support_fact_ids=support_fact_ids,
        inclusion_status=inclusion_status,
    )
    chain = _confirmed_claim_chain(
        closure=closure,
        issuer_id=issuer_id,
        cutoff=cutoff,
        statement=statement,
        supporting_fact_ids=support_fact_ids,
    )
    if chain is None:
        raise AccountingReconciliationError(
            f"{purpose}.{input_role} lacks a named-human reviewed inclusion proof"
        )
    return chain[2].claim_id, chain[1].decision_id


def _term_binding(
    *,
    input_role: str,
    fact_ids: tuple[str, ...],
    required_status: str,
    proof: tuple[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "input_role": input_role,
        "fact_ids": list(fact_ids),
        "inclusion_status": (
            "not_required"
            if required_status == "not_required"
            else required_status
            if fact_ids
            else "none_identified_after_review"
        ),
        "claim_id": proof[0] if proof else None,
        "review_decision_id": proof[1] if proof else None,
        "missing_evidence": [],
        "reason_codes": [],
    }


def _build_formula_decision(
    *,
    purpose: str,
    role_fact_ids: dict[str, tuple[str, ...]],
    proofs: dict[str, tuple[str, str]],
    ledger: dict[str, dict[str, Any]],
) -> AccountingFactDecision:
    policy = FORMULA_POLICIES[purpose]
    bindings = tuple(
        _term_binding(
            input_role=term.input_role,
            fact_ids=role_fact_ids[term.input_role],
            required_status=term.required_inclusion_status,
            proof=proofs.get(term.input_role),
        )
        for term in policy.terms
    )
    inputs = tuple(fact_id for term in policy.terms for fact_id in role_fact_ids[term.input_role])
    output, calculation_id, roots, lineage = _derive_fact(
        purpose=purpose,
        input_fact_ids=inputs,
        ledger=ledger,
    )
    ledger[output["fact_id"]] = output
    return AccountingFactDecision(
        purpose=purpose,
        disposition="emitted",
        output_fact_id=output["fact_id"],
        calculation_id=calculation_id,
        input_fact_ids=inputs,
        root_fact_ids=roots,
        term_bindings=bindings,
        lineage_status=lineage,
        reason_codes=(),
    )


def _alias_fact(
    *,
    role: str,
    parent_id: str,
    ledger: dict[str, dict[str, Any]],
) -> str:
    parent = ledger[parent_id]
    fact_id = f"derived:phase5c:{role}:{parent['period_end']}"
    ledger[fact_id] = {
        **parent,
        "fact_id": fact_id,
        "concept": role,
        "raw": False,
        "parent_fact_ids": [parent_id],
        "derivation": COMMON_EQUITY_ALIAS_DERIVATIONS[role],
        "source_location": f"{role} deterministic Phase 5C-1 alias",
    }
    return fact_id


def _build_check(
    *,
    check_id: str,
    role_fact_ids: dict[str, str],
    ledger: dict[str, dict[str, Any]],
    perimeter_id: str,
) -> dict[str, Any]:
    policy = PERIOD_ALIGNMENT_POLICIES[check_id]
    role_facts = {role: ledger[fact_id] for role, fact_id in role_fact_ids.items()}
    roots_by_role = {
        role: tuple(sorted(_raw_roots(fact_id, ledger))) for role, fact_id in role_fact_ids.items()
    }
    difference = sum(
        sign * float(role_facts[role]["value"]) for role, sign in policy.equation_terms
    )
    tolerance = ACCOUNTING_RECONCILIATION_RELATIVE_TOLERANCE * max(
        1.0, *(abs(float(item["value"])) for item in role_facts.values())
    )
    seen: set[str] = set()
    overlapping = False
    for roots in roots_by_role.values():
        if seen.intersection(roots):
            overlapping = True
        seen.update(roots)
    if abs(difference) > tolerance:
        status = "blocked"
        reason_codes = [
            "clean_surplus_reconciliation_failed"
            if check_id == "clean_surplus"
            else "balance_sheet_reconciliation_failed"
        ]
    elif overlapping:
        status = "reconciles_by_construction"
        reason_codes = [
            "clean_surplus_by_construction"
            if check_id == "clean_surplus"
            else "balance_sheet_by_construction"
        ]
    else:
        status, reason_codes = "reconciles_independently", []
    if check_id == "clean_surplus":
        start = role_facts["comprehensive_income_attributable_to_common"]["period_start"]
        end = role_facts["comprehensive_income_attributable_to_common"]["period_end"]
    else:
        start = None
        end = next(iter({role_facts[role]["period_end"] for role in policy.stock_roles}))
    return {
        "status": status,
        "role_fact_ids": role_fact_ids,
        "fact_ids": sorted(role_fact_ids.values()),
        "root_fact_ids": sorted({root for roots in roots_by_role.values() for root in roots}),
        "measurement_period": {"start": start, "end": end},
        "stock_measurement_dates": {
            role: role_facts[role]["period_end"] for role in policy.stock_roles
        },
        "stock_root_fact_ids": {role: list(roots_by_role[role]) for role in policy.stock_roles},
        "currency": role_facts[next(iter(role_facts))]["currency"],
        "unit": role_facts[next(iter(role_facts))]["unit"],
        "common_equity_perimeter_id": perimeter_id,
        "difference": difference,
        "tolerance": tolerance,
        "reason_codes": reason_codes,
    }


def _economic_binding_template(
    *,
    issuer_id: str,
    measurement_end: str,
    economic_identity: str,
    root_fact_ids: tuple[str, ...],
) -> dict[str, Any]:
    kind = {
        "method_base": "aggregate_perimeter",
        "nonoperating_asset": "aggregate_perimeter",
        "debt": "instrument",
        "debt_equivalent": "instrument",
        "lease_liability": "instrument",
        "unfunded_pension": "plan",
        "preferred_stock": "security_class",
        "noncontrolling_interest": "aggregate_perimeter",
        "option_or_dilution_claim": "plan",
        "other_senior_claim": "instrument",
    }[economic_identity]
    identity_value = (
        f"phase5c:{economic_identity}:"
        f"{canonical_sha256({'root_fact_ids': sorted(root_fact_ids)})[:20]}"
    )
    security_class = identity_value if kind == "security_class" else None
    scope_id = f"scope:{issuer_id}:issuer-wide"
    return {
        "binding_id": f"economic-claim-binding:{canonical_sha256(identity_value)[:20]}",
        "economic_identity": economic_identity,
        "identity_kind": kind,
        "identity_value": identity_value,
        "scope_id": scope_id,
        "measurement_end": measurement_end,
        "security_class": security_class,
        "economic_claim_key": _economic_claim_key(
            issuer_id=issuer_id,
            identity_kind=kind,
            identity_value=identity_value,
            scope_id=scope_id,
            measurement_end=measurement_end,
            security_class=security_class,
        ),
        "status": "confirmed",
        "root_fact_ids": list(root_fact_ids),
        "identity_evidence_fact_ids": list(root_fact_ids),
        "diluted_share_treatment": "not_applicable",
        "diluted_share_fact_ids": [],
        "candidate_id": None,
        "review_decision_id": None,
        "claim_id": None,
        "missing_evidence": [],
        "reason_codes": [],
    }


def _economic_claim_contracts(
    *,
    decisions: tuple[AccountingFactDecision, ...],
    ledger: dict[str, dict[str, Any]],
    closure: dict[str, tuple[str, Any]],
    issuer_id: str,
    cutoff: str,
    measurement_end: str,
) -> tuple[
    tuple[FrozenMap, ...],
    tuple[AnalyticalClaimCandidate, ...],
    tuple[AnalyticalClaimReviewDecision, ...],
    tuple[Claim, ...],
]:
    roots = {
        root_id
        for decision in decisions
        if decision.purpose
        in {"invested_capital", "net_operating_assets", "net_financial_obligations"}
        for root_id in decision.root_fact_ids
    }
    groups: dict[str, list[str]] = defaultdict(list)
    for root_id in sorted(roots):
        concept = ledger[root_id]["concept"]
        identity = ACCOUNT_CONCEPT_POLICIES[concept].bridge_role or "method_base"
        groups[identity].append(root_id)
    bindings: list[FrozenMap] = []
    candidates: list[AnalyticalClaimCandidate] = []
    reviews: list[AnalyticalClaimReviewDecision] = []
    claims: list[Claim] = []
    for identity, root_ids in sorted(groups.items()):
        if identity == "option_or_dilution_claim" and any(
            float(ledger[root_id]["value"]) != 0 for root_id in root_ids
        ):
            raise AccountingReconciliationError(
                "positive option claims require a later reviewed dilution treatment"
            )
        template = _economic_binding_template(
            issuer_id=issuer_id,
            measurement_end=measurement_end,
            economic_identity=identity,
            root_fact_ids=tuple(root_ids),
        )
        statement = _economic_claim_review_statement(freeze(template))
        chain = _confirmed_claim_chain(
            closure=closure,
            issuer_id=issuer_id,
            cutoff=cutoff,
            statement=statement,
            supporting_fact_ids=tuple(root_ids),
        )
        if chain is None:
            raise AccountingReconciliationError(
                f"{identity} lacks a named-human reviewed economic identity"
            )
        candidate, review, claim = chain
        template.update(
            {
                "candidate_id": candidate.candidate_id,
                "review_decision_id": review.decision_id,
                "claim_id": claim.claim_id,
            }
        )
        bindings.append(freeze(template))
        candidates.append(candidate)
        reviews.append(review)
        claims.append(claim)
    return (
        tuple(bindings),
        tuple(sorted(candidates, key=lambda item: item.candidate_id)),
        tuple(sorted(reviews, key=lambda item: item.decision_id)),
        tuple(sorted(claims, key=lambda item: item.claim_id)),
    )


def _kernel_compatibility_validate(
    *,
    kernel_repository: Path,
    ledger_payload: dict[str, Any],
    checks: dict[str, dict[str, Any]],
) -> None:
    schema = _load_kernel_fact_schema(kernel_repository)
    _validate_ledger(ledger_payload, schema)
    script = r"""
import json
import sys
from owner_valuation import FactLedger
from owner_valuation.validation import validate_balance_sheet, validate_clean_surplus

payload = json.load(sys.stdin)
FactLedger.from_dict(payload["ledger"])
results = {}
for check_id in ("balance_sheet", "clean_surplus"):
    values = payload[check_id]
    try:
        if check_id == "balance_sheet":
            validate_balance_sheet(values["assets"], values["liabilities"], values["equity"])
        else:
            validate_clean_surplus(**values)
    except Exception:
        results[check_id] = "blocked"
    else:
        results[check_id] = "pass"
json.dump(results, sys.stdout, sort_keys=True)
"""
    facts = {item["fact_id"]: item for item in ledger_payload["facts"]}
    balance_roles = checks["balance_sheet"]["role_fact_ids"]
    clean_roles = checks["clean_surplus"]["role_fact_ids"]
    payload = {
        "ledger": ledger_payload,
        "balance_sheet": {
            "assets": facts[balance_roles["total_assets"]]["value"],
            "liabilities": facts[balance_roles["adjusted_total_liabilities"]]["value"],
            "equity": facts[balance_roles["common_equity"]]["value"],
        },
        "clean_surplus": {
            "beginning_equity": facts[clean_roles["beginning_common_equity"]]["value"],
            "comprehensive_income": facts[
                clean_roles["comprehensive_income_attributable_to_common"]
            ]["value"],
            "net_distributions_to_owners": facts[clean_roles["net_distributions_to_owners"]][
                "value"
            ],
            "ending_equity": facts[clean_roles["ending_common_equity"]]["value"],
        },
    }
    env = os.environ.copy()
    kernel_src = str(kernel_repository.resolve() / "src")
    env["PYTHONPATH"] = kernel_src + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        replay = json.loads(completed.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise AccountingReconciliationError(
            "pinned kernel accounting compatibility validation failed"
        ) from exc
    expected = {
        check_id: "blocked" if checks[check_id]["status"] == "blocked" else "pass"
        for check_id in ("balance_sheet", "clean_surplus")
    }
    if replay != expected:
        raise AccountingReconciliationError(
            "pinned kernel accounting validators disagree with the research controls"
        )


def compile_accounting_reformulation(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
) -> AccountingReconciliationResult:
    """Compile the deterministic price-blind Phase 5C-1 accounting predecessor."""

    mapping = compile_price_blind_fact_ledger(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
    )
    bundle, run_manifest, closure = _load_context(Path(bundle_artifact_directory), graph)
    bound_graph = replace(
        graph,
        manifests=tuple(
            run_manifest if item.run_id == run_manifest.run_id else item for item in graph.manifests
        ),
        research_bundles=(bundle,),
    )
    readiness = assess_method_readiness(graph=bound_graph, mapping_result=mapping)
    if (
        bundle.bundle_id != mapping.research_bundle_id
        or bundle.bundle_fingerprint != mapping.research_bundle_fingerprint
        or bundle.dependency_closure_sha256 != mapping.dependency_closure_sha256
        or bundle.component_lock_sha256 != mapping.component_lock_sha256
    ):
        raise AccountingReconciliationError("Phase 5B replay differs from the bound Bundle")
    base_payload = to_json_value(mapping.ledger_payload)
    reporting_currency = base_payload["reporting_currency"]
    documents = {
        identifier: item for identifier, (kind, item) in closure.items() if kind == "SourceDocument"
    }
    base_fact_ids = {item["fact_id"] for item in base_payload["facts"]}
    candidate_rows: list[dict[str, Any]] = []
    candidate_documents: dict[str, SourceDocument] = {}
    for identifier, (kind, item) in sorted(closure.items()):
        if kind != "Fact" or identifier in base_fact_ids or item.concept not in _RAW_INPUT_CONCEPTS:
            continue
        document = documents.get(item.source_document_id)
        if (
            document is None
            or item.issuer_id != bundle.issuer_id
            or document.issuer_id != bundle.issuer_id
        ):
            raise AccountingReconciliationError("Phase 5C input source identity is incomplete")
        row = _research_fact_to_kernel(
            item,
            document,
            reporting_currency=reporting_currency,
            cutoff=bundle.data_cutoff_date,
        )
        candidate_rows.append(row)
        candidate_documents[row["fact_id"]] = document
    selected_by_key = _unique_by_semantic_key(candidate_rows)
    base_facts = {item["fact_id"]: dict(item) for item in base_payload["facts"]}
    anchors: dict[str, set[str]] = defaultdict(set)
    for row in (*base_facts.values(), *selected_by_key.values()):
        if row["concept"] in {"total_assets", "total_liabilities", "total_equity"}:
            anchors[row["concept"]].add(row["period_end"])
    common_dates = (
        set.intersection(
            *(anchors[concept] for concept in ("total_assets", "total_liabilities", "total_equity"))
        )
        if all(
            anchors[concept] for concept in ("total_assets", "total_liabilities", "total_equity")
        )
        else set()
    )
    if not common_dates:
        raise AccountingReconciliationError(
            "current total assets, total liabilities, and total equity do not share a date"
        )
    measurement_end = max(common_dates)
    comprehensive = [
        row
        for row in selected_by_key.values()
        if row["concept"] == "comprehensive_income_attributable_to_common"
        and row["period_end"] == measurement_end
    ]
    if len(comprehensive) != 1 or comprehensive[0]["period_start"] is None:
        raise AccountingReconciliationError(
            "one attributable-to-common comprehensive-income flow is required"
        )
    flow_start = comprehensive[0]["period_start"]
    current_selected = [
        row
        for row in selected_by_key.values()
        if (
            row["period_end"] == measurement_end
            and (
                ACCOUNT_CONCEPT_POLICIES[row["concept"]].period_kind == "stock"
                or (row["period_start"], row["period_end"]) == (flow_start, measurement_end)
            )
        )
    ]
    required_new_concepts = {
        "total_equity",
        "comprehensive_income_attributable_to_common",
        *OWNER_TRANSACTION_CONCEPTS,
    }
    selected_concepts = {row["concept"] for row in current_selected}
    missing = required_new_concepts.difference(selected_concepts)
    if missing:
        raise AccountingReconciliationError(
            "owner transaction or accounting perimeter evidence is incomplete: "
            + ", ".join(sorted(missing))
        )
    ledger = dict(base_facts)
    for row in current_selected:
        ledger[row["fact_id"]] = row
    sources = {item["source_id"]: dict(item) for item in base_payload["sources"]}
    for row in current_selected:
        document = candidate_documents[row["fact_id"]]
        sources.setdefault(document.document_id, _source_ref(document))
    account_decisions = _account_decisions(
        ledger=ledger,
        measurement_end=measurement_end,
        closure=closure,
        issuer_id=bundle.issuer_id,
        cutoff=bundle.data_cutoff_date,
    )
    classified_by_role: dict[str, tuple[str, ...]] = {}
    for role in (
        "operating_asset",
        "operating_liability",
        "financial_asset",
        "financial_obligation",
    ):
        classified_by_role[role] = tuple(
            sorted(item.fact_id for item in account_decisions if item.account_role == role)
        )
        if not classified_by_role[role]:
            raise AccountingReconciliationError(f"{role} has no closed accounting evidence")
    non_common = {
        item.fact_id: item for item in account_decisions if item.concept in _PERIMETER_CONCEPTS
    }
    anchor_ids = {
        concept: next(
            item["fact_id"]
            for item in ledger.values()
            if item["concept"] == concept and item["period_end"] == measurement_end
        )
        for concept in ("total_assets", "total_liabilities", "total_equity")
    }
    non_common_roles = {
        "common_equity": (
            "included_non_common_equity_claims",
            tuple(
                sorted(
                    key
                    for key, item in non_common.items()
                    if item.perimeter_disposition["total_equity"] == "included"
                )
            ),
            (anchor_ids["total_equity"],),
            "included_in_total_equity",
        ),
        "adjusted_total_liabilities": (
            "equity_classified_non_common_claims",
            tuple(
                sorted(
                    key
                    for key, item in non_common.items()
                    if item.perimeter_disposition["reported_liabilities"] == "excluded"
                )
            ),
            (anchor_ids["total_liabilities"],),
            "outside_reported_liabilities",
        ),
        "net_financial_obligations": (
            "nfo_non_common_equity_claims",
            tuple(
                sorted(
                    key
                    for key, item in non_common.items()
                    if item.perimeter_disposition["financial_obligations"] == "excluded"
                )
            ),
            classified_by_role["financial_obligation"],
            "not_in_reported_liabilities",
        ),
    }
    proofs: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
    for purpose, (role, fact_ids, anchors_for_proof, inclusion) in non_common_roles.items():
        support = tuple(sorted({*fact_ids, *anchors_for_proof}))
        proofs[purpose][role] = _formula_inclusion_proof(
            closure=closure,
            issuer_id=bundle.issuer_id,
            cutoff=bundle.data_cutoff_date,
            purpose=purpose,
            input_role=role,
            measurement_end=measurement_end,
            fact_ids=fact_ids,
            support_fact_ids=support,
            inclusion_status=inclusion if fact_ids else "none_identified_after_review",
        )
    owner_by_concept = {
        concept: next(
            row["fact_id"]
            for row in current_selected
            if row["concept"] == concept
            and (row["period_start"], row["period_end"]) == (flow_start, measurement_end)
        )
        for concept in OWNER_TRANSACTION_CONCEPTS
    }
    owner_coverage = {
        concept: {
            "status": "official_zero" if float(ledger[fact_id]["value"]) == 0 else "observed",
            "fact_id": fact_id,
            "claim_id": None,
            "review_decision_id": None,
            "missing_evidence": [],
            "reason_codes": [],
        }
        for concept, fact_id in owner_by_concept.items()
    }
    role_inputs = {
        "common_equity": {
            "total_equity": (anchor_ids["total_equity"],),
            "included_non_common_equity_claims": non_common_roles["common_equity"][1],
        },
        "adjusted_total_liabilities": {
            "total_liabilities": (anchor_ids["total_liabilities"],),
            "equity_classified_non_common_claims": non_common_roles["adjusted_total_liabilities"][
                1
            ],
        },
        "net_operating_assets": {
            "operating_asset_components": classified_by_role["operating_asset"],
            "operating_liability_components": classified_by_role["operating_liability"],
        },
        "net_financial_obligations": {
            "financial_obligation_components": classified_by_role["financial_obligation"],
            "nfo_non_common_equity_claims": non_common_roles["net_financial_obligations"][1],
            "financial_asset_components": classified_by_role["financial_asset"],
        },
        "net_distributions_to_owners": {
            "distributions": tuple(
                owner_by_concept[concept]
                for concept in (
                    "common_dividends",
                    "common_share_repurchases",
                    "other_common_owner_distributions",
                )
            ),
            "contributions": tuple(
                owner_by_concept[concept]
                for concept in (
                    "common_equity_issuance_proceeds",
                    "equity_settled_sbc_owner_contribution",
                    "other_common_owner_contributions",
                )
            ),
        },
    }
    decisions: list[AccountingFactDecision] = []
    for purpose in (
        "common_equity",
        "adjusted_total_liabilities",
        "net_operating_assets",
        "net_financial_obligations",
        "net_distributions_to_owners",
    ):
        decisions.append(
            _build_formula_decision(
                purpose=purpose,
                role_fact_ids=role_inputs[purpose],
                proofs=proofs[purpose],
                ledger=ledger,
            )
        )
    noa_id = next(
        item.output_fact_id for item in decisions if item.purpose == "net_operating_assets"
    )
    decisions.append(
        _build_formula_decision(
            purpose="invested_capital",
            role_fact_ids={"net_operating_assets": (str(noa_id),)},
            proofs={},
            ledger=ledger,
        )
    )
    decisions_tuple = tuple(decisions)
    common_equity_id = str(
        next(item.output_fact_id for item in decisions_tuple if item.purpose == "common_equity")
    )
    owner_distribution_id = str(
        next(
            item.output_fact_id
            for item in decisions_tuple
            if item.purpose == "net_distributions_to_owners"
        )
    )
    beginning_date = (date.fromisoformat(flow_start) - timedelta(days=1)).isoformat()
    beginning_candidates = [
        item
        for item in ledger.values()
        if item["concept"] == "common_equity"
        and item["period_end"] == beginning_date
        and item["raw"] is True
    ]
    if len(beginning_candidates) != 1:
        raise AccountingReconciliationError(
            "clean surplus requires one consecutive beginning common-equity Fact"
        )
    beginning_alias = _alias_fact(
        role="beginning_common_equity",
        parent_id=beginning_candidates[0]["fact_id"],
        ledger=ledger,
    )
    ending_alias = _alias_fact(
        role="ending_common_equity",
        parent_id=common_equity_id,
        ledger=ledger,
    )
    noa_output = str(
        next(
            item.output_fact_id
            for item in decisions_tuple
            if item.purpose == "net_operating_assets"
        )
    )
    nfo_output = str(
        next(
            item.output_fact_id
            for item in decisions_tuple
            if item.purpose == "net_financial_obligations"
        )
    )
    adjusted_liabilities = str(
        next(
            item.output_fact_id
            for item in decisions_tuple
            if item.purpose == "adjusted_total_liabilities"
        )
    )
    comprehensive_id = comprehensive[0]["fact_id"]
    perimeter_id = f"common-equity-perimeter:{bundle.issuer_id}:{measurement_end}"
    checks = {
        "balance_sheet": _build_check(
            check_id="balance_sheet",
            role_fact_ids={
                "total_assets": anchor_ids["total_assets"],
                "adjusted_total_liabilities": adjusted_liabilities,
                "common_equity": common_equity_id,
            },
            ledger=ledger,
            perimeter_id=perimeter_id,
        ),
        "clean_surplus": _build_check(
            check_id="clean_surplus",
            role_fact_ids={
                "beginning_common_equity": beginning_alias,
                "ending_common_equity": ending_alias,
                "comprehensive_income_attributable_to_common": comprehensive_id,
                "net_distributions_to_owners": owner_distribution_id,
            },
            ledger=ledger,
            perimeter_id=perimeter_id,
        ),
        "noa_nfo_common_equity": _build_check(
            check_id="noa_nfo_common_equity",
            role_fact_ids={
                "net_operating_assets": noa_output,
                "net_financial_obligations": nfo_output,
                "common_equity": common_equity_id,
            },
            ledger=ledger,
            perimeter_id=perimeter_id,
        ),
    }
    economic = _economic_claim_contracts(
        decisions=decisions_tuple,
        ledger=ledger,
        closure=closure,
        issuer_id=bundle.issuer_id,
        cutoff=bundle.data_cutoff_date,
        measurement_end=measurement_end,
    )
    check_statuses = {item["status"] for item in checks.values()}
    status = (
        "blocked"
        if "blocked" in check_statuses
        else "partial"
        if "reconciles_by_construction" in check_statuses
        else "pass"
    )
    reason_codes = tuple(
        sorted({reason for check in checks.values() for reason in check["reason_codes"]})
    )
    ledger_payload = {
        "schema_version": base_payload["schema_version"],
        "entity_id": base_payload["entity_id"],
        "valuation_date": base_payload["valuation_date"],
        "reporting_currency": reporting_currency,
        "sources": sorted(sources.values(), key=lambda item: item["source_id"]),
        "facts": sorted(ledger.values(), key=lambda item: item["fact_id"]),
    }
    selected_ids = tuple(sorted(row["fact_id"] for row in current_selected))
    result = AccountingReconciliationResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        dependency_closure_sha256=bundle.dependency_closure_sha256,
        component_lock_sha256=bundle.component_lock_sha256,
        phase5b_mapping_fingerprint=mapping.fingerprint,
        phase5b_mapping_result=mapping,
        phase5b_readiness_fingerprint=readiness.fingerprint,
        phase5b_readiness_result=readiness,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        base_ledger_fingerprint=canonical_sha256(base_payload),
        selected_input_fact_ids=selected_ids,
        selected_input_source_ids=tuple(
            sorted({ledger[fact_id]["source_id"] for fact_id in selected_ids})
        ),
        ledger_payload=FrozenMap(ledger_payload),
        account_decisions=account_decisions,
        fact_decisions=decisions_tuple,
        economic_claim_bindings=economic[0],
        economic_claim_candidates=economic[1],
        economic_claim_review_decisions=economic[2],
        economic_claims=economic[3],
        owner_transaction_coverage=FrozenMap(owner_coverage),
        checks=FrozenMap(checks),
        status=status,
        reason_codes=reason_codes,
    )
    _kernel_compatibility_validate(
        kernel_repository=Path(kernel_repository),
        ledger_payload=to_json_value(result.ledger_payload),
        checks=to_json_value(result.checks),
    )
    return result
