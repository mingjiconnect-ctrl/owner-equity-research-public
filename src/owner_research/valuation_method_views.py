"""Internal Phase 5C-3 deterministic MethodView compiler."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from .fingerprints import FrozenMap, to_json_value
from .validation import ContractGraph
from .valuation_accounting_policies import (
    FORMULA_POLICIES,
    METHODS,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
    phase5c_policy_sha256,
)
from .valuation_accounting_quality import compile_accounting_quality_adjustments
from .valuation_accounting_types import (
    MethodViewCompilationResult,
    _claim_records_for_roots,
    _economic_binding_index,
    _ultimate_raw_roots,
)


class MethodViewCompilationError(ValueError):
    """Raised when method views cannot close without duplicate root consumption."""


def _reconciliation_outputs(reconciliation: Any) -> dict[str, str]:
    return {
        FORMULA_POLICIES[item.purpose].output_concept: item.output_fact_id
        for item in reconciliation.fact_decisions
        if item.disposition == "emitted" and item.output_fact_id is not None
    }


def _base_consumption_records(
    *,
    reconciliation: Any,
    ledger: dict[str, dict[str, Any]],
) -> set[tuple[str, str, str, str, str, str, str]]:
    outputs = _reconciliation_outputs(reconciliation)
    binding_index = _economic_binding_index(reconciliation)
    records: set[tuple[str, str, str, str, str, str, str]] = set()
    base_groups = (
        (
            "mckinsey",
            "mckinsey_invested_capital",
            "method-base:mckinsey:invested-capital",
            ("invested_capital",),
        ),
        (
            "penman",
            "penman_noa_nfo",
            "method-base:penman:noa-nfo",
            ("net_operating_assets", "net_financial_obligations"),
        ),
    )
    for method, channel, group_id, concepts in base_groups:
        fact_ids = {outputs[concept] for concept in concepts if concept in outputs}
        if len(fact_ids) != len(concepts):
            raise MethodViewCompilationError(f"{method} method base is incomplete")
        roots = {
            root_id
            for fact_id in fact_ids
            for root_id in _ultimate_raw_roots(fact_id, ledger)
        }
        roots_by_channel: dict[str, set[str]] = defaultdict(set)
        for root_id in roots:
            binding = binding_index.get(root_id)
            if binding is None or binding["status"] != "confirmed":
                raise MethodViewCompilationError(
                    "method-base root lacks a confirmed economic Claim binding"
                )
            identity = binding["economic_identity"]
            effective_channel = (
                "penman_nfo" if method == "penman" and identity != "method_base" else channel
            )
            roots_by_channel[effective_channel].add(root_id)
        for effective_channel, channel_roots in roots_by_channel.items():
            records.update(
                _claim_records_for_roots(
                    root_ids=channel_roots,
                    binding_index=binding_index,
                    channel=effective_channel,
                    method=method,
                    group_id=group_id,
                    consumption_kind="method_base",
                )
            )
    return records


def _adjustment_consumption_records(
    *,
    quality: Any,
    ledger: dict[str, dict[str, Any]],
) -> set[tuple[str, str, str, str, str, str, str]]:
    binding_index = _economic_binding_index(quality.reconciliation_result)
    records: set[tuple[str, str, str, str, str, str, str]] = set()
    for decision in quality.adjustment_decisions:
        if decision.disposition != "compiled":
            continue
        identities = {
            binding_index[root_id]["economic_identity"]
            for root_id in decision.root_fact_ids
        }
        channels = {
            (
                "mckinsey_equity_bridge"
                if decision.method == "mckinsey" and identity != "method_base"
                else "mckinsey_invested_capital"
                if decision.method == "mckinsey"
                else "penman_nfo"
                if identity != "method_base"
                else "penman_noa_nfo"
            )
            for identity in identities
        }
        if len(channels) != 1:
            raise MethodViewCompilationError(
                "method adjustment mixes registered economic channels"
            )
        roots = set(decision.root_fact_ids)
        if any(root_id not in ledger for root_id in roots):
            raise MethodViewCompilationError("method adjustment root is not in the quality ledger")
        records.update(
            _claim_records_for_roots(
                root_ids=roots,
                binding_index=binding_index,
                channel=next(iter(channels)),
                method=decision.method,
                group_id=decision.adjustment_group_id,
                consumption_kind="economic_deduction",
            )
        )
    return records


def _record_payload(
    records: set[tuple[str, str, str, str, str, str, str]],
) -> tuple[dict[str, str], ...]:
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


def _kernel_method_view_compatibility(
    *,
    kernel_repository: Path,
    ledger_payload: dict[str, Any],
    adjustments: tuple[dict[str, Any], ...],
) -> None:
    script = r"""
import json
import sys
from owner_valuation import FactLedger, MethodAdjustment, MethodView
from owner_valuation.facts import AdjustmentCategory, ViewName

payload = json.load(sys.stdin)
ledger = FactLedger.from_dict(payload["ledger"])
by_method = {"mckinsey": [], "penman": []}
views = {
    "mckinsey": ViewName.MCKINSEY,
    "penman": ViewName.PENMAN,
}
for item in payload["adjustments"]:
    by_method[item["method"]].append(
        MethodAdjustment(
            adjustment_id=item["adjustment_id"],
            adjustment_group_id=item["adjustment_group_id"],
            view=views[item["method"]],
            category=AdjustmentCategory(item["category"]),
            target_fact_id=item["target_fact_id"],
            amount=item["amount"],
            source_fact_ids=tuple(item["source_fact_ids"]),
            rationale=item["rationale"],
            evidence_source_ids=tuple(item["evidence_source_ids"]),
        )
    )
for method, view in views.items():
    compiled = MethodView(view, ledger, by_method[method])
    for item in by_method[method]:
        compiled.value(item.target_fact_id)
        compiled.source_fact_ids(item.target_fact_id)
json.dump({"status": "pass"}, sys.stdout)
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
                {"ledger": ledger_payload, "adjustments": adjustments},
                sort_keys=True,
                separators=(",", ":"),
            ),
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        response = json.loads(completed.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise MethodViewCompilationError("pinned kernel MethodView validation failed") from exc
    if response != {"status": "pass"}:
        raise MethodViewCompilationError("pinned kernel MethodView response drifted")


def compile_method_views(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
) -> MethodViewCompilationResult:
    """Compile McKinsey/Penman price-blind MethodView fragments in memory."""

    quality = compile_accounting_quality_adjustments(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
    )
    ledger_payload = to_json_value(quality.ledger_payload)
    ledger = {item["fact_id"]: item for item in ledger_payload["facts"]}
    views: dict[str, list[dict[str, Any]]] = {method: [] for method in METHODS}
    kernel_adjustments: list[dict[str, Any]] = []
    for decision in quality.adjustment_decisions:
        if decision.disposition != "compiled":
            continue
        amount = ledger[decision.amount_fact_id]
        views[decision.method].append(
            {
                "adjustment_id": decision.adjustment_id,
                "target_fact_id": decision.target_fact_id,
                "target_concept": decision.target_concept,
                "target_bridge_role": decision.target_bridge_role,
                "amount_fact_id": decision.amount_fact_id,
            }
        )
        kernel_adjustments.append(
            {
                "method": decision.method,
                "adjustment_id": decision.adjustment_id,
                "adjustment_group_id": decision.adjustment_group_id,
                "category": decision.category,
                "target_fact_id": decision.target_fact_id,
                "amount": amount["value"],
                "source_fact_ids": list(decision.source_fact_ids),
                "rationale": decision.rationale,
                "evidence_source_ids": list(decision.evidence_source_ids),
            }
        )
    records = _base_consumption_records(
        reconciliation=quality.reconciliation_result,
        ledger=ledger,
    )
    records.update(_adjustment_consumption_records(quality=quality, ledger=ledger))
    _kernel_method_view_compatibility(
        kernel_repository=Path(kernel_repository),
        ledger_payload=ledger_payload,
        adjustments=tuple(kernel_adjustments),
    )
    status_by_method = {
        method: (
            "blocked"
            if quality.status_by_method[method] == "blocked"
            or any(
                item.method == method and item.disposition == "blocked"
                for item in quality.adjustment_decisions
            )
            else "partial"
            if quality.status_by_method[method] == "partial"
            else "pass"
        )
        for method in METHODS
    }
    reasons = tuple(
        sorted(
            {
                *quality.reason_codes,
                *(
                    reason
                    for item in quality.adjustment_decisions
                    if item.disposition == "blocked"
                    for reason in item.reason_codes
                ),
            }
        )
    )
    return MethodViewCompilationResult(
        issuer_id=quality.issuer_id,
        data_cutoff_date=quality.data_cutoff_date,
        reconciliation_fingerprint=quality.reconciliation_fingerprint,
        reconciliation_result=quality.reconciliation_result,
        quality_fingerprint=quality.fingerprint,
        quality_result=quality,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=FrozenMap(ledger_payload),
        adjustment_decisions=quality.adjustment_decisions,
        method_views=FrozenMap(views),
        consumption_records=_record_payload(records),
        status_by_method=FrozenMap(status_by_method),
        reason_codes=reasons,
    )
