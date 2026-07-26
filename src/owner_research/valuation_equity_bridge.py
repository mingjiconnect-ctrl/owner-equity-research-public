"""Internal Phase 5C-4 deterministic nine-role equity-bridge compiler."""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .fingerprints import FrozenMap, to_json_value
from .validation import ContractGraph
from .valuation_accounting_policies import (
    ACCOUNT_CONCEPT_POLICIES,
    BRIDGE_AGGREGATE_DERIVATIONS,
    BRIDGE_ROLES,
    BRIDGE_UNRESOLVED_REASON_SEVERITY,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
    bridge_role_policy,
    phase5c_policy_sha256,
)
from .valuation_accounting_types import (
    EquityBridgeCompilationResult,
    EquityBridgeRoleDecision,
    MethodViewCompilationResult,
    _claim_records_for_roots,
    _economic_binding_index,
    _ultimate_raw_roots,
)
from .valuation_method_views import compile_method_views


class EquityBridgeCompilationError(ValueError):
    """Raised when the nine-role bridge cannot be compiled without inference."""


_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def _current_measurement_end(method_view: MethodViewCompilationResult) -> str:
    outputs = {
        item.output_fact_id
        for item in method_view.reconciliation_result.fact_decisions
        if item.purpose == "invested_capital"
        and item.disposition == "emitted"
        and item.output_fact_id is not None
    }
    if len(outputs) != 1:
        raise EquityBridgeCompilationError("current invested-capital perimeter is ambiguous")
    ledger = {item["fact_id"]: item for item in method_view.ledger_payload["facts"]}
    return ledger[next(iter(outputs))]["period_end"]


def _diluted_share_lineage(
    method_view: MethodViewCompilationResult,
    ledger: dict[str, dict[str, Any]],
    *,
    measurement_end: str,
) -> tuple[str, tuple[str, ...]]:
    phase5b_facts = {
        item["fact_id"]: item
        for item in method_view.reconciliation_result.phase5b_mapping_result.ledger_payload[
            "facts"
        ]
    }
    candidates = tuple(
        sorted(
            (
                item
                for item in phase5b_facts.values()
                if item["concept"] == "diluted_shares"
                and item["period_end"] == measurement_end
                and ledger.get(item["fact_id"]) == to_json_value(item)
            ),
            key=lambda item: item["fact_id"],
        )
    )
    if len(candidates) != 1:
        raise EquityBridgeCompilationError(
            "current diluted shares require one unambiguous Phase 5B Fact"
        )
    selected = candidates[0]
    roots = tuple(sorted(_ultimate_raw_roots(selected["fact_id"], ledger)))
    return selected["fact_id"], roots


def _unresolved(
    *,
    role: str,
    reason: str,
    missing: str,
) -> EquityBridgeRoleDecision:
    return EquityBridgeRoleDecision(
        role=role,
        status="unresolved",
        fact_id=None,
        evidence_fact_ids=(),
        root_fact_ids=(),
        claim_id=None,
        review_decision_id=None,
        rationale="The registered bridge role cannot be closed from frozen evidence.",
        missing_evidence=(missing,),
        reason_codes=(reason,),
    )


def _aggregate_fact(
    *,
    role: str,
    facts: tuple[dict[str, Any], ...],
    measurement_end: str,
) -> dict[str, Any]:
    value = sum(float(item["value"]) for item in facts)
    return {
        "fact_id": f"derived:phase5c:equity-bridge:{role}:{measurement_end}",
        "concept": facts[0]["concept"],
        "value": int(value) if value.is_integer() else value,
        "unit": facts[0]["unit"],
        "category": facts[0]["category"],
        "source_id": facts[0]["source_id"],
        "source_location": f"Phase 5C-4 reviewed {role} aggregate",
        "as_of_date": facts[0]["as_of_date"],
        "currency": facts[0]["currency"],
        "period_start": facts[0]["period_start"],
        "period_end": facts[0]["period_end"],
        "confidence": min(
            (item["confidence"] for item in facts), key=_CONFIDENCE_ORDER.get
        ),
        "raw": False,
        "parent_fact_ids": [item["fact_id"] for item in facts],
        "derivation": BRIDGE_AGGREGATE_DERIVATIONS[role],
        "equity_bridge_role": role,
    }


def _role_decision(
    *,
    role: str,
    candidates: tuple[dict[str, Any], ...],
    binding_index: dict[str, FrozenMap],
    diluted_roots: set[str],
    preconsumed_claims: set[str],
    reporting_currency: str,
    measurement_end: str,
) -> tuple[EquityBridgeRoleDecision, dict[str, Any] | None]:
    if not candidates:
        reason = (
            "nonoperating_cash_evidence_missing"
            if role == "nonoperating_asset"
            else "bridge_role_coverage_incomplete"
        )
        return (
            _unresolved(
                role=role,
                reason=reason,
                missing=f"No current official numeric evidence closes {role}.",
            ),
            None,
        )
    fact_ids = tuple(item["fact_id"] for item in candidates)
    bindings = tuple(binding_index.get(fact_id) for fact_id in fact_ids)
    if any(
        binding is None
        or binding["status"] != "confirmed"
        or binding["economic_identity"] != role
        for binding in bindings
    ):
        return (
            _unresolved(
                role=role,
                reason="bridge_state_not_replayed",
                missing=f"Reviewed economic identity is incomplete for {role}.",
            ),
            None,
        )
    claim_keys = {binding["economic_claim_key"] for binding in bindings}
    if None in claim_keys or claim_keys.intersection(preconsumed_claims):
        return (
            _unresolved(
                role=role,
                reason="bridge_root_overlap",
                missing=f"The {role} claim is already consumed in the McKinsey method view.",
            ),
            None,
        )
    if diluted_roots.intersection(fact_ids):
        return (
            _unresolved(
                role=role,
                reason="bridge_diluted_share_overlap",
                missing=f"The {role} roots overlap diluted-share lineage.",
            ),
            None,
        )
    expected_category = bridge_role_policy(role).kernel_category
    expected_unit = f"{reporting_currency} millions"
    if any(
        item["category"] != expected_category
        or item["currency"] != reporting_currency
        or item["unit"] != expected_unit
        for item in candidates
    ):
        reason = (
            "bridge_fact_currency_mismatch"
            if any(
                item["currency"] != reporting_currency or item["unit"] != expected_unit
                for item in candidates
            )
            else "bridge_fact_category_mismatch"
        )
        return (
            _unresolved(
                role=role,
                reason=reason,
                missing=f"The {role} facts do not match the registered unit/category policy.",
            ),
            None,
        )
    periods = {
        (item["period_start"], item["period_end"], item["as_of_date"])
        for item in candidates
    }
    if periods != {(None, measurement_end, measurement_end)}:
        return (
            _unresolved(
                role=role,
                reason="bridge_state_not_replayed",
                missing=f"The {role} stock facts do not share the current measurement date.",
            ),
            None,
        )
    source_ids = {item["source_id"] for item in candidates}
    if len(source_ids) != 1:
        return (
            _unresolved(
                role=role,
                reason="bridge_multi_source_aggregation",
                missing=f"The {role} components cannot be aggregated across sources.",
            ),
            None,
        )
    values = tuple(item["value"] for item in candidates)
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
        for value in values
    ):
        return (
            _unresolved(
                role=role,
                reason="bridge_fact_not_positive_magnitude",
                missing=f"The {role} evidence is not a nonnegative magnitude.",
            ),
            None,
        )
    if role == "option_or_dilution_claim":
        treatments = {binding["diluted_share_treatment"] for binding in bindings}
        if treatments == {"blocked"}:
            return (
                _unresolved(
                    role=role,
                    reason="bridge_diluted_share_overlap",
                    missing="The reviewed option/dilution treatment remains blocked.",
                ),
                None,
            )
        if treatments == {"included"} and len(bindings) == 1:
            binding = bindings[0]
            return (
                EquityBridgeRoleDecision(
                    role=role,
                    status="not_applicable",
                    fact_id=None,
                    evidence_fact_ids=fact_ids,
                    root_fact_ids=fact_ids,
                    claim_id=binding["claim_id"],
                    review_decision_id=binding["review_decision_id"],
                    rationale="The reviewed claim is already included in diluted shares.",
                    missing_evidence=(),
                    reason_codes=(),
                ),
                None,
            )
        if treatments not in ({"excluded"}, {"not_applicable"}):
            return (
                _unresolved(
                    role=role,
                    reason="bridge_state_not_replayed",
                    missing="The option/dilution treatment is ambiguous.",
                ),
                None,
            )
    if all(float(value) == 0 for value in values):
        return (
            EquityBridgeRoleDecision(
                role=role,
                status="explicitly_absent",
                fact_id=None,
                evidence_fact_ids=fact_ids,
                root_fact_ids=fact_ids,
                claim_id=None,
                review_decision_id=None,
                rationale="The current official filing reports numeric zero evidence.",
                missing_evidence=(),
                reason_codes=(),
            ),
            None,
        )
    aggregate = _aggregate_fact(
        role=role,
        facts=candidates,
        measurement_end=measurement_end,
    )
    return (
        EquityBridgeRoleDecision(
            role=role,
            status="modeled",
            fact_id=aggregate["fact_id"],
            evidence_fact_ids=(*fact_ids, aggregate["fact_id"]),
            root_fact_ids=fact_ids,
            claim_id=None,
            review_decision_id=None,
            rationale="Current same-source components were aggregated without overlap.",
            missing_evidence=(),
            reason_codes=(),
        ),
        aggregate,
    )


def _consumption_records(
    *,
    method_view: MethodViewCompilationResult,
    decisions: tuple[EquityBridgeRoleDecision, ...],
) -> tuple[dict[str, str], ...]:
    binding_index = _economic_binding_index(method_view.reconciliation_result)
    records = {
        (
            item["root_fact_id"],
            item["economic_claim_key"],
            item["economic_identity"],
            item["channel"],
            item["method"],
            item["group_id"],
            item["consumption_kind"],
        )
        for item in method_view.consumption_records
    }
    for decision in decisions:
        if decision.status != "modeled":
            continue
        records.update(
            _claim_records_for_roots(
                root_ids=set(decision.root_fact_ids),
                binding_index=binding_index,
                channel="mckinsey_equity_bridge",
                method="mckinsey",
                group_id=f"equity-bridge:{decision.role}",
                consumption_kind="economic_deduction",
            )
        )
    option_bindings = {
        item["binding_id"]: item
        for item in method_view.reconciliation_result.economic_claim_bindings
        if item["economic_identity"] == "option_or_dilution_claim"
        and item["diluted_share_treatment"] == "included"
    }
    for binding in option_bindings.values():
        for method in ("mckinsey", "penman"):
            records.update(
                _claim_records_for_roots(
                    root_ids=set(binding["root_fact_ids"]),
                    binding_index=binding_index,
                    channel=f"{method}_diluted_shares",
                    method=method,
                    group_id=f"diluted-shares:{binding['binding_id']}",
                    consumption_kind="economic_deduction",
                )
            )
    fields = (
        "root_fact_id",
        "economic_claim_key",
        "economic_identity",
        "channel",
        "method",
        "group_id",
        "consumption_kind",
    )
    return tuple(dict(zip(fields, row, strict=True)) for row in sorted(records))


def _kernel_fact_ledger_compatibility(
    *,
    kernel_repository: Path,
    ledger_payload: dict[str, Any],
    modeled_fact_ids: tuple[str, ...],
) -> None:
    script = r"""
import json
import sys
from owner_valuation import FactLedger

payload = json.load(sys.stdin)
ledger = FactLedger.from_dict(payload["ledger"])
tagged = sorted(
    fact.fact_id for fact in ledger.facts.values() if fact.equity_bridge_role is not None
)
json.dump({"tagged": tagged}, sys.stdout)
"""
    env = os.environ.copy()
    kernel_src = str(kernel_repository.resolve() / "src")
    env["PYTHONPATH"] = kernel_src + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(
                {"ledger": ledger_payload}, sort_keys=True, separators=(",", ":")
            ),
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        response = json.loads(completed.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise EquityBridgeCompilationError("pinned kernel FactLedger validation failed") from exc
    if response != {"tagged": sorted(modeled_fact_ids)}:
        raise EquityBridgeCompilationError("pinned kernel bridge-role shape drifted")


def _compile_equity_bridge_result(
    *,
    method_view: MethodViewCompilationResult,
    kernel_repository: Path,
) -> EquityBridgeCompilationResult:
    ledger_payload = to_json_value(method_view.ledger_payload)
    ledger = {item["fact_id"]: item for item in ledger_payload["facts"]}
    measurement_end = _current_measurement_end(method_view)
    diluted_fact_id, diluted_root_ids = _diluted_share_lineage(
        method_view,
        ledger,
        measurement_end=measurement_end,
    )
    binding_index = _economic_binding_index(method_view.reconciliation_result)
    preconsumed_claims = {
        item["economic_claim_key"]
        for item in method_view.consumption_records
        if item["method"] == "mckinsey"
        and item["consumption_kind"] != "validation"
        and item["channel"] != "mckinsey_invested_capital"
    }
    decisions: list[EquityBridgeRoleDecision] = []
    additions: list[dict[str, Any]] = []
    for role in BRIDGE_ROLES:
        candidates = tuple(
            sorted(
                (
                    item
                    for item in ledger.values()
                    if item["raw"] is True
                    and item["period_end"] == measurement_end
                    and item["equity_bridge_role"] is None
                    and ACCOUNT_CONCEPT_POLICIES.get(item["concept"]) is not None
                    and ACCOUNT_CONCEPT_POLICIES[item["concept"]].bridge_role == role
                ),
                key=lambda item: item["fact_id"],
            )
        )
        decision, addition = _role_decision(
            role=role,
            candidates=candidates,
            binding_index=binding_index,
            diluted_roots=set(diluted_root_ids),
            preconsumed_claims=preconsumed_claims,
            reporting_currency=ledger_payload["reporting_currency"],
            measurement_end=measurement_end,
        )
        decisions.append(decision)
        if addition is not None:
            additions.append(addition)
    ledger_payload["facts"] = sorted(
        (*ledger_payload["facts"], *additions), key=lambda item: item["fact_id"]
    )
    modeled = tuple(
        decision.fact_id
        for decision in decisions
        if decision.status == "modeled" and decision.fact_id is not None
    )
    _kernel_fact_ledger_compatibility(
        kernel_repository=kernel_repository,
        ledger_payload=ledger_payload,
        modeled_fact_ids=modeled,
    )
    unresolved_reasons = {
        reason
        for decision in decisions
        if decision.status == "unresolved"
        for reason in decision.reason_codes
    }
    reasons = set(unresolved_reasons)
    if not modeled:
        reasons.add("kernel_bridge_item_required")
    status = (
        "blocked"
        if any(
            BRIDGE_UNRESOLVED_REASON_SEVERITY[reason] == "blocked"
            for reason in unresolved_reasons
        )
        else "partial"
        if unresolved_reasons or not modeled
        else "complete"
    )
    bridge_items = tuple(
        {"item_id": f"bridge:{decision.role}", "fact_id": decision.fact_id}
        for decision in decisions
        if decision.status == "modeled"
    )
    role_assertions = tuple(
        {
            "role": decision.role,
            "status": decision.status,
            "fact_id": decision.fact_id,
            "source_fact_ids": list(decision.evidence_fact_ids),
            "rationale": decision.rationale,
        }
        for decision in decisions
    )
    return EquityBridgeCompilationResult(
        issuer_id=method_view.issuer_id,
        data_cutoff_date=method_view.data_cutoff_date,
        reconciliation_fingerprint=method_view.reconciliation_fingerprint,
        method_view_fingerprint=method_view.fingerprint,
        method_view_result=method_view,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=FrozenMap(ledger_payload),
        diluted_shares_fact_id=diluted_fact_id,
        diluted_share_root_fact_ids=diluted_root_ids,
        role_decisions=tuple(decisions),
        bridge_items=bridge_items,
        role_assertions=role_assertions,
        consumption_records=_consumption_records(
            method_view=method_view,
            decisions=tuple(decisions),
        ),
        status=status,
        kernel_request_compatible=bool(modeled) and not unresolved_reasons,
        reason_codes=tuple(sorted(reasons)),
    )


def compile_equity_bridge(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
) -> EquityBridgeCompilationResult:
    """Compile the price-blind nine-role bridge in memory after MethodView freeze."""

    method_view = compile_method_views(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
    )
    return _compile_equity_bridge_result(
        method_view=method_view,
        kernel_repository=kernel_repository,
    )
