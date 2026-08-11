"""Internal append-only compiler for the pinned rc.2 valuation request.

The compiler consumes a validated Phase 5D price-blind freeze and the market-reference
vertical slice.  It never fetches market data and never invokes valuation mathematics.
Only current-share lineage, the governed quote, and derived market equity are appended to
the frozen FactLedger; assumption entries remain byte-identical and are rebound solely to
the resulting FactLedger fingerprint.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .component_lock import file_sha256
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .valuation_kernel_projection import (
    CurrentShareKernelProjection,
    KernelNumericProjectionWitness,
    project_current_share_lineage,
)
from .valuation_market_execution_policies import (
    FINAL_REQUEST_POLICY_ID,
    FINAL_REQUEST_POLICY_VERSION,
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_SCHEMA_SHA256,
    PINNED_KERNEL_TAG,
)
from .valuation_market_snapshot import PreparedMarketReference
from .valuation_owner_preparation import OwnerValuationPreparationResult
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult


class FinalRequestCompilationError(ValueError):
    """Raised when the complete request cannot be compiled without inference."""


_KERNEL_TAG_OBJECT = "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
_MODEL_SHARE_UNIT = "millions shares"
_MARKET_EQUITY_DERIVATION = (
    "market_price_per_current_common_share * common_shares_outstanding"
)


def _git(repository: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repository), *args],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise FinalRequestCompilationError("pinned kernel checkout cannot be verified") from exc


def _verify_kernel(repository: Path) -> tuple[Path, dict[str, dict[str, Any]]]:
    kernel = Path(repository).expanduser().resolve()
    if (
        _git(kernel, "rev-parse", "HEAD") != PINNED_KERNEL_COMMIT
        or _git(kernel, "rev-parse", f"{PINNED_KERNEL_TAG}^{{}}")
        != PINNED_KERNEL_COMMIT
        or _git(kernel, "rev-parse", f"refs/tags/{PINNED_KERNEL_TAG}")
        != _KERNEL_TAG_OBJECT
    ):
        raise FinalRequestCompilationError("kernel tag, commit, or tag object changed")
    schemas: dict[str, dict[str, Any]] = {}
    for relative, expected_sha in sorted(PINNED_KERNEL_SCHEMA_SHA256.items()):
        path = kernel / relative
        if not path.is_file() or file_sha256(path) != expected_sha:
            raise FinalRequestCompilationError(f"pinned kernel Schema changed: {relative}")
        try:
            schemas[relative] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise FinalRequestCompilationError(
                f"pinned kernel Schema cannot be read: {relative}"
            ) from exc
    return kernel, schemas


def _validate_request_schema(
    request: dict[str, Any], schemas: dict[str, dict[str, Any]]
) -> None:
    fact_schema = schemas["schemas/fact-ledger.schema.json"]
    assumption_schema = schemas["schemas/assumption-ledger.schema.json"]
    request_schema = schemas["schemas/valuation-request.schema.json"]
    registry = (
        Registry()
        .with_resource(fact_schema["$id"], Resource.from_contents(fact_schema))
        .with_resource(assumption_schema["$id"], Resource.from_contents(assumption_schema))
    )
    errors = sorted(
        Draft202012Validator(
            request_schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).iter_errors(request),
        key=lambda item: tuple(str(part) for part in item.path),
    )
    if errors:
        first = errors[0]
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}" for part in first.path
        )
        raise FinalRequestCompilationError(
            f"pinned request Schema rejected the compiled payload at {path}: {first.message}"
        )


def _runtime_ledger_preflight(kernel: Path, request: dict[str, Any]) -> None:
    """Use only rc.2 immutable input types; valuation functions remain untouched."""

    script = r"""
import json
import sys
from owner_valuation.assumptions import AssumptionLedger
from owner_valuation.contracts import validate_request
from owner_valuation.facts import FactLedger

payload = json.load(sys.stdin)
validate_request(payload)
ledger = FactLedger.from_dict(payload["fact_ledger"])
assumptions = AssumptionLedger.from_dict(payload["assumption_ledger"], ledger)
if ledger.to_dict() != payload["fact_ledger"]:
    raise RuntimeError("FactLedger canonical bytes changed")
json.dump({"fact_ledger_fingerprint": ledger.fingerprint,
           "assumption_count": len(assumptions.assumptions)}, sys.stdout,
          sort_keys=True, separators=(",", ":"))
"""
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(kernel / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            input=canonical_json(request),
            text=True,
            capture_output=True,
            check=True,
            env=environment,
            timeout=30,
        )
        replay = json.loads(completed.stdout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise FinalRequestCompilationError(
            "pinned rc.2 input types rejected the compiled request"
        ) from exc
    if replay.get("fact_ledger_fingerprint") != canonical_sha256(
        request["fact_ledger"]
    ) or replay.get("assumption_count") != len(
        request["assumption_ledger"]["assumptions"]
    ):
        raise FinalRequestCompilationError("pinned input-type fingerprints do not replay")


@dataclass(frozen=True, slots=True)
class FinalFactLedgerCompilationResult:
    policy_id: str
    policy_version: str
    base_ledger_sha256: str
    base_source_fingerprints: tuple[tuple[str, str], ...]
    base_fact_fingerprints: tuple[tuple[str, str], ...]
    current_share_projection: CurrentShareKernelProjection
    quote_projection_witness: KernelNumericProjectionWitness
    market_equity_projection_witness: KernelNumericProjectionWitness
    added_source_ids: tuple[str, ...]
    added_fact_ids: tuple[str, ...]
    fact_ledger_payload: FrozenMap

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            FINAL_REQUEST_POLICY_ID,
            FINAL_REQUEST_POLICY_VERSION,
        ):
            raise ValueError("final FactLedger policy identity is invalid")
        if self.current_share_projection.status != "eligible":
            raise ValueError("final FactLedger lacks eligible current-share evidence")
        sources = tuple(sorted(self.base_source_fingerprints))
        facts = tuple(sorted(self.base_fact_fingerprints))
        added_sources = tuple(sorted(set(self.added_source_ids)))
        added_facts = tuple(sorted(set(self.added_fact_ids)))
        payload = freeze(self.fact_ledger_payload)
        if not added_sources or not added_facts:
            raise ValueError("final FactLedger did not append market lineage")
        object.__setattr__(self, "base_source_fingerprints", sources)
        object.__setattr__(self, "base_fact_fingerprints", facts)
        object.__setattr__(self, "added_source_ids", added_sources)
        object.__setattr__(self, "added_fact_ids", added_facts)
        object.__setattr__(self, "fact_ledger_payload", payload)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class FinalAssumptionLedgerCompilationResult:
    assumption_entries_sha256: str
    prior_fact_ledger_fingerprint: str
    final_fact_ledger_fingerprint: str
    assumption_ledger_payload: FrozenMap

    def __post_init__(self) -> None:
        payload = freeze(self.assumption_ledger_payload)
        if (
            payload["fact_ledger_fingerprint"] != self.final_fact_ledger_fingerprint
            or canonical_sha256(payload["assumptions"]) != self.assumption_entries_sha256
            or self.prior_fact_ledger_fingerprint == self.final_fact_ledger_fingerprint
        ):
            raise ValueError("final AssumptionLedger rebinding is invalid")
        object.__setattr__(self, "assumption_ledger_payload", payload)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class FinalValuationRequestCompilationResult:
    status: str
    issuer_id: str
    valuation_date: str
    price_blind_input_fingerprint: str
    prepared_market_reference_fingerprint: str | None
    fact_ledger_result: FinalFactLedgerCompilationResult | None
    assumption_ledger_result: FinalAssumptionLedgerCompilationResult | None
    request_payload: FrozenMap | None
    canonical_request_json: str | None
    request_sha256: str | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"compiled", "blocked", "specialist_required"}:
            raise ValueError("final request status is not registered")
        issues = tuple(sorted(set(self.issue_codes)))
        if self.status == "compiled":
            if (
                self.fact_ledger_result is None
                or self.assumption_ledger_result is None
                or self.request_payload is None
                or self.canonical_request_json is None
                or self.request_sha256 is None
                or self.prepared_market_reference_fingerprint is None
                or issues
                or canonical_json(self.request_payload) != self.canonical_request_json
                or canonical_sha256(self.request_payload) != self.request_sha256
            ):
                raise ValueError("compiled valuation request is incomplete")
        elif any(
            item is not None
            for item in (
                self.fact_ledger_result,
                self.assumption_ledger_result,
                self.request_payload,
                self.canonical_request_json,
                self.request_sha256,
                self.prepared_market_reference_fingerprint,
            )
        ) or not issues:
            raise ValueError("non-compiled valuation request promoted an artifact")
        object.__setattr__(
            self,
            "request_payload",
            freeze(self.request_payload) if self.request_payload is not None else None,
        )
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _noncompiled(
    *,
    preparation: OwnerValuationPreparationResult,
    status: str,
    issue: str,
) -> FinalValuationRequestCompilationResult:
    return FinalValuationRequestCompilationResult(
        status=status,
        issuer_id=preparation.issuer_id,
        valuation_date=preparation.data_cutoff_date,
        price_blind_input_fingerprint=preparation.price_blind_input_fingerprint,
        prepared_market_reference_fingerprint=None,
        fact_ledger_result=None,
        assumption_ledger_result=None,
        request_payload=None,
        canonical_request_json=None,
        request_sha256=None,
        issue_codes=(issue,),
    )


def _append_by_id(
    base: list[dict[str, Any]],
    additions: tuple[dict[str, Any], ...],
    *,
    field: str,
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    index = {str(item[field]): dict(item) for item in base}
    if len(index) != len(base):
        raise FinalRequestCompilationError(f"base ledger repeats {field}")
    added: list[str] = []
    for item in additions:
        identifier = str(item[field])
        if identifier in index:
            if canonical_json(index[identifier]) != canonical_json(item):
                raise FinalRequestCompilationError(f"appended object collides at {identifier}")
            continue
        index[identifier] = dict(item)
        added.append(identifier)
    return [index[key] for key in sorted(index)], tuple(sorted(added))


def _market_source(prepared: PreparedMarketReference) -> dict[str, Any]:
    document = prepared.market_source
    if (
        document.document_id != prepared.snapshot.quote_source_document_id
        or document.authority_level != "market_reference"
        or document.content_sha256
        != prepared.snapshot.raw_evidence["raw_response_sha256"]
    ):
        raise FinalRequestCompilationError("market SourceDocument does not replay Snapshot")
    return {
        "source_id": document.document_id,
        "title": f"Reviewed market close ({document.document_type})",
        "publisher": document.issuer_id,
        "published_date": document.published_date,
        "retrieved_at": document.retrieved_at,
        "locator": (
            f"document_id={document.document_id};content_sha256={document.content_sha256}"
        ),
        "url": document.source_url,
        "local_path": None,
        "primary": False,
    }


def _market_facts(
    prepared: PreparedMarketReference,
    share_projection: CurrentShareKernelProjection,
    reporting_currency: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    KernelNumericProjectionWitness,
    KernelNumericProjectionWitness,
]:
    snapshot = prepared.snapshot
    quote_decimal = Decimal(snapshot.quote_price_decimal)
    market_decimal = Decimal(snapshot.market_equity["value_decimal"])
    quote_witness = KernelNumericProjectionWitness.compile(
        label=f"quote:{snapshot.quote_fact_id}",
        authoritative_decimal=quote_decimal,
    )
    share_fact = next(
        item
        for item in share_projection.facts
        if item["fact_id"] == share_projection.current_share_fact_id
    )
    projected_market_value = quote_witness.kernel_value * float(share_fact["value"])
    market_witness = KernelNumericProjectionWitness.compile_from_projected_binary64(
        label=f"market-equity:{snapshot.market_equity['calculation_id']}",
        authoritative_decimal=market_decimal,
        projected_value=projected_market_value,
        scale_divisor=Decimal(1_000_000),
    )
    if market_decimal != quote_decimal * Decimal(snapshot.share_basis[
        "current_common_shares_outstanding_decimal"
    ]):
        raise FinalRequestCompilationError("authoritative market-equity Decimal changed")
    quote = prepared.quote_fact
    if (
        quote.fact_id != snapshot.quote_fact_id
        or quote.period["end"] != snapshot.trading_date
        or quote.source_document_id != prepared.market_source.document_id
        or Decimal(str(quote.value)) != quote_decimal
    ):
        raise FinalRequestCompilationError("research quote Fact does not replay Snapshot")
    quote_fact = {
        "fact_id": quote.fact_id,
        "concept": "market_price_per_current_common_share",
        "value": quote_witness.kernel_value,
        "unit": f"{reporting_currency} per share",
        "category": "market_price",
        "source_id": prepared.market_source.document_id,
        "source_location": quote.source_locator,
        "as_of_date": snapshot.trading_date,
        "currency": reporting_currency,
        "period_start": None,
        "period_end": None,
        "confidence": "high",
        "raw": True,
        "parent_fact_ids": [],
        "derivation": None,
        "equity_bridge_role": None,
    }
    calculation = prepared.market_equity_calculation
    if (
        calculation.calculation_id != snapshot.market_equity["calculation_id"]
        or tuple(calculation.input_fact_ids)
        != (quote.fact_id, share_projection.current_share_fact_id)
        or calculation.input_assumption_ids
        or Decimal(str(calculation.value)) != market_decimal
    ):
        raise FinalRequestCompilationError(
            "research market-equity CalculationResult does not replay Snapshot"
        )
    confidence = max(
        (str(share_fact["confidence"]), "high"),
        key=lambda item: {"high": 0, "medium": 1, "low": 2, "unknown": 3}[item],
    )
    market_fact = {
        "fact_id": f"derived:{calculation.calculation_id}",
        "concept": "market_equity_value",
        "value": market_witness.kernel_value,
        "unit": f"{reporting_currency} millions",
        "category": "market_price",
        "source_id": prepared.market_source.document_id,
        "source_location": f"derived:{calculation.calculation_id}",
        "as_of_date": snapshot.trading_date,
        "currency": reporting_currency,
        "period_start": None,
        "period_end": None,
        "confidence": confidence,
        "raw": False,
        "parent_fact_ids": [quote_fact["fact_id"], share_projection.current_share_fact_id],
        "derivation": _MARKET_EQUITY_DERIVATION,
        "equity_bridge_role": None,
    }
    return quote_fact, market_fact, quote_witness, market_witness


def _compile_fact_ledger(
    *,
    base_ledger: dict[str, Any],
    prepared: PreparedMarketReference,
) -> FinalFactLedgerCompilationResult:
    snapshot = prepared.snapshot
    if (
        base_ledger.get("entity_id") != snapshot.issuer_id
        or base_ledger.get("valuation_date") != snapshot.trading_date
        or base_ledger.get("reporting_currency") != snapshot.quote_currency
    ):
        raise FinalRequestCompilationError(
            "market reference and price-blind FactLedger identity/date/currency differ"
        )
    projection = project_current_share_lineage(prepared)
    if projection.status == "specialist_required":
        raise FinalRequestCompilationError("current-share lineage requires specialist routing")
    if projection.status != "eligible":
        raise FinalRequestCompilationError("current-share lineage is not kernel eligible")
    reporting_currency = str(base_ledger["reporting_currency"])
    quote, market, quote_witness, market_witness = _market_facts(
        prepared,
        projection,
        reporting_currency,
    )
    base_sources = [dict(item) for item in base_ledger["sources"]]
    base_facts = [dict(item) for item in base_ledger["facts"]]
    base_source_fingerprints = tuple(
        sorted((str(item["source_id"]), canonical_sha256(item)) for item in base_sources)
    )
    base_fact_fingerprints = tuple(
        sorted((str(item["fact_id"]), canonical_sha256(item)) for item in base_facts)
    )
    projected_sources = tuple(to_json_value(item) for item in projection.sources)
    sources, share_source_ids = _append_by_id(
        base_sources,
        projected_sources,
        field="source_id",
    )
    market_source = _market_source(prepared)
    sources, market_source_ids = _append_by_id(
        sources,
        (market_source,),
        field="source_id",
    )
    projected_facts = tuple(to_json_value(item) for item in projection.facts)
    facts, share_fact_ids = _append_by_id(base_facts, projected_facts, field="fact_id")
    facts, market_fact_ids = _append_by_id(facts, (quote, market), field="fact_id")
    payload = {
        "schema_version": "1.0.0",
        "entity_id": base_ledger["entity_id"],
        "valuation_date": base_ledger["valuation_date"],
        "reporting_currency": reporting_currency,
        "sources": sources,
        "facts": facts,
    }
    for identifier, fingerprint in base_source_fingerprints:
        item = next(value for value in payload["sources"] if value["source_id"] == identifier)
        if canonical_sha256(item) != fingerprint:
            raise FinalRequestCompilationError("price-blind SourceRef changed during append")
    for identifier, fingerprint in base_fact_fingerprints:
        item = next(value for value in payload["facts"] if value["fact_id"] == identifier)
        if canonical_sha256(item) != fingerprint:
            raise FinalRequestCompilationError("price-blind Fact changed during append")
    return FinalFactLedgerCompilationResult(
        policy_id=FINAL_REQUEST_POLICY_ID,
        policy_version=FINAL_REQUEST_POLICY_VERSION,
        base_ledger_sha256=canonical_sha256(base_ledger),
        base_source_fingerprints=base_source_fingerprints,
        base_fact_fingerprints=base_fact_fingerprints,
        current_share_projection=projection,
        quote_projection_witness=quote_witness,
        market_equity_projection_witness=market_witness,
        added_source_ids=(*share_source_ids, *market_source_ids),
        added_fact_ids=(*share_fact_ids, *market_fact_ids),
        fact_ledger_payload=freeze(payload),
    )


def _compile_assumption_ledger(
    base: dict[str, Any],
    final_fact_ledger: dict[str, Any],
) -> FinalAssumptionLedgerCompilationResult:
    assumptions_before = to_json_value(base["assumptions"])
    entries_sha = canonical_sha256(assumptions_before)
    final_fingerprint = canonical_sha256(final_fact_ledger)
    payload = {
        "schema_version": base["schema_version"],
        "fact_ledger_fingerprint": final_fingerprint,
        "assumptions": assumptions_before,
    }
    if canonical_json(payload["assumptions"]) != canonical_json(base["assumptions"]):
        raise FinalRequestCompilationError("assumption entries changed during ledger rebinding")
    return FinalAssumptionLedgerCompilationResult(
        assumption_entries_sha256=entries_sha,
        prior_fact_ledger_fingerprint=str(base["fact_ledger_fingerprint"]),
        final_fact_ledger_fingerprint=final_fingerprint,
        assumption_ledger_payload=freeze(payload),
    )


def _request_company(phase5c: dict[str, Any], prepared: PreparedMarketReference) -> dict[str, Any]:
    classification = phase5c["reconciliation_result"]["phase5b_readiness_result"][
        "classification"
    ]
    if (
        classification["specialist_route"] != "none"
        or classification["company_type"] != "nonfinancial_operating_company"
    ):
        raise FinalRequestCompilationError("company classification requires specialist routing")
    source_fact_ids = tuple(sorted(classification["mapped_fact_ids"]))
    if not source_fact_ids:
        raise FinalRequestCompilationError("company classification lacks mapped evidence")
    return {
        "name": prepared.snapshot.issuer_id,
        "type": classification["company_type"],
        "classification_rationale": classification["rationale"],
        "source_fact_ids": list(source_fact_ids),
    }


def _request_routing(
    phase5c: dict[str, Any], assumptions: dict[str, Any]
) -> dict[str, Any]:
    if phase5c["specialist_route"] != "none" or any(
        phase5c["method_panels"][method]["status"] != "ready_for_phase5d"
        for method in ("mckinsey", "penman")
    ):
        raise FinalRequestCompilationError("Phase 5C is not ready for the core dual panel")
    assumption_fact_ids = sorted(
        {
            fact_id
            for item in assumptions["assumptions"]
            for fact_id in item["source_fact_ids"]
        }
    )
    if not assumption_fact_ids:
        raise FinalRequestCompilationError("near-term assumptions lack source Facts")
    output: dict[str, Any] = {}
    for key, assessment in phase5c["routing_assessments"].items():
        if key in {"required_data_complete", "credible_near_term_earnings"}:
            output[key] = {
                "value": True,
                "rationale": (
                    "The named-human-reviewed price-blind assumptions and complete request "
                    "inputs are present."
                    if key == "required_data_complete"
                    else "Named-human-reviewed near-term forecast assumptions are present."
                ),
                "source_fact_ids": assumption_fact_ids,
            }
            continue
        if assessment["status"] != "satisfied" or assessment["value"] is not True:
            raise FinalRequestCompilationError(f"routing assessment is not satisfied: {key}")
        fact_ids = sorted(assessment["evidence_fact_ids"])
        if not fact_ids:
            raise FinalRequestCompilationError(f"routing assessment lacks evidence: {key}")
        output[key] = {
            "value": True,
            "rationale": assessment["rationale"],
            "source_fact_ids": fact_ids,
        }
    return output


def _request_accounting(
    phase5c: dict[str, Any], final_ledger: dict[str, Any]
) -> dict[str, Any]:
    checks = phase5c["reconciliation_result"]["checks"]
    balance = checks["balance_sheet"]
    clean = checks["clean_surplus"]
    if balance["status"] != "reconciles_independently" or clean[
        "status"
    ] != "reconciles_independently":
        raise FinalRequestCompilationError("accounting checks are not independently reconciled")
    quality = phase5c["quality_result"]
    if any(quality["status_by_method"][method] != "pass" for method in ("mckinsey", "penman")):
        raise FinalRequestCompilationError("accounting quality blocks a dual-panel request")
    decisions = {item["finding_id"]: item for item in quality["issue_decisions"]}
    issues = []
    for item in quality["kernel_quality_issues"]:
        decision = decisions.get(item["issue_id"])
        if decision is None:
            raise FinalRequestCompilationError("accounting issue lacks its reviewed decision")
        issues.append(
            {
                **item,
                "rationale": (
                    f"Reviewed accounting-quality finding {item['issue_id']} was classified "
                    f"as {decision['disposition']}."
                ),
            }
        )
    ledger_facts = {item["fact_id"]: item for item in final_ledger["facts"]}
    liability_decisions = tuple(
        item
        for item in phase5c["reconciliation_result"]["fact_decisions"]
        if item["purpose"] == "adjusted_total_liabilities"
    )
    if len(liability_decisions) != 1 or liability_decisions[0]["disposition"] != "emitted":
        raise FinalRequestCompilationError(
            "adjusted-liabilities decision is unavailable or unresolved"
        )
    liability_terms = {
        item["input_role"]: tuple(item["fact_ids"])
        for item in liability_decisions[0]["term_bindings"]
    }
    if set(liability_terms) != {
        "total_liabilities",
        "equity_classified_non_common_claims",
    }:
        raise FinalRequestCompilationError(
            "adjusted-liabilities decision has an invalid term perimeter"
        )
    if liability_terms["equity_classified_non_common_claims"]:
        raise FinalRequestCompilationError(
            "equity-classified non-common claims require specialist accounting"
        )
    liability_roots = liability_terms["total_liabilities"]
    total_liabilities = tuple(
        ledger_facts[fact_id]
        for fact_id in liability_roots
        if fact_id in ledger_facts
        and ledger_facts[fact_id]["concept"] == "total_liabilities"
        and ledger_facts[fact_id]["raw"] is True
        and ledger_facts[fact_id]["period_start"] is None
        and ledger_facts[fact_id]["period_end"] is None
        and ledger_facts[fact_id]["currency"] == final_ledger["reporting_currency"]
        and ledger_facts[fact_id]["unit"]
        == f"{final_ledger['reporting_currency']} millions"
    )
    if len(total_liabilities) != 1:
        raise FinalRequestCompilationError(
            "balance-sheet reconciliation lacks one raw total-liabilities root"
        )
    balance_fact_ids = (
        balance["role_fact_ids"]["total_assets"],
        total_liabilities[0]["fact_id"],
        balance["role_fact_ids"]["common_equity"],
    )
    if any(fact_id not in ledger_facts for fact_id in balance_fact_ids):
        raise FinalRequestCompilationError("balance-sheet reconciliation Fact is absent")
    balance_facts = tuple(ledger_facts[fact_id] for fact_id in balance_fact_ids)
    if (
        len({item["as_of_date"] for item in balance_facts}) != 1
        or any(item["period_start"] is not None for item in balance_facts)
        or any(item["period_end"] is not None for item in balance_facts)
        or {item["currency"] for item in balance_facts}
        != {final_ledger["reporting_currency"]}
        or {item["unit"] for item in balance_facts}
        != {f"{final_ledger['reporting_currency']} millions"}
    ):
        raise FinalRequestCompilationError(
            "balance-sheet reconciliation perimeter is not comparable"
        )
    return {
        "balance_sheet": {
            "assets_fact_id": balance["role_fact_ids"]["total_assets"],
            "liabilities_fact_id": total_liabilities[0]["fact_id"],
            "equity_fact_id": balance["role_fact_ids"]["common_equity"],
        },
        "clean_surplus": {
            "beginning_equity_fact_id": clean["role_fact_ids"][
                "beginning_common_equity"
            ],
            "comprehensive_income_fact_id": clean["role_fact_ids"][
                "comprehensive_income_attributable_to_common"
            ],
            "net_distributions_fact_id": clean["role_fact_ids"][
                "net_distributions_to_owners"
            ],
            "ending_equity_fact_id": clean["role_fact_ids"]["ending_common_equity"],
        },
        "quality_issues": issues,
    }


def _request_method_views(phase5c: dict[str, Any]) -> dict[str, Any]:
    method = phase5c["method_view_result"]
    decisions = {
        item["adjustment_id"]: item
        for item in method["adjustment_decisions"]
        if item["disposition"] == "compiled"
    }
    output: dict[str, list[dict[str, Any]]] = {}
    for name in ("mckinsey", "penman"):
        entries = []
        for item in method["method_views"][name]:
            decision = decisions.get(item["adjustment_id"])
            if decision is None or decision["method"] != name:
                raise FinalRequestCompilationError("MethodView entry lacks compiled decision")
            entries.append(
                {
                    "adjustment_id": item["adjustment_id"],
                    "adjustment_group_id": decision["adjustment_group_id"],
                    "category": decision["category"],
                    "target_fact_id": item["target_fact_id"],
                    "amount_fact_id": item["amount_fact_id"],
                    "rationale": decision["rationale"],
                }
            )
        output[f"{name}_adjustments"] = entries
    return output


def _validate_forecast_axis(
    *,
    valuation_date: str,
    mckinsey_scenarios: list[dict[str, Any]],
    penman_payload: dict[str, Any],
) -> None:
    from datetime import date

    anchor = date.fromisoformat(valuation_date)

    def anniversary(offset: int) -> date:
        try:
            return anchor.replace(year=anchor.year + offset)
        except ValueError:
            # A February 29 valuation date uses the last valid day in later
            # non-leap years; the rule is deterministic and price blind.
            return anchor.replace(year=anchor.year + offset, day=28)

    def annual_axis(
        rows: list[dict[str, Any]],
        label: str,
        *,
        first_offset: int,
    ) -> tuple[str, ...]:
        if not rows:
            raise FinalRequestCompilationError(f"{label} forecast is empty")
        values: list[str] = []
        for index, row in enumerate(rows, start=first_offset):
            current = date.fromisoformat(row["period_end"])
            if current != anniversary(index):
                raise FinalRequestCompilationError(
                    f"{label} forecast is not based on the final valuation-date annual axis"
                )
            values.append(current.isoformat())
        return tuple(values)

    scenario_axes = {
        annual_axis(
            list(item["forecast"]),
            f"McKinsey {item['name']}",
            first_offset=1,
        )
        for item in mckinsey_scenarios
    }
    if len(scenario_axes) != 1:
        raise FinalRequestCompilationError("McKinsey scenarios do not share one annual axis")
    penman_axis = annual_axis(
        list(penman_payload["forecast"]),
        "Penman",
        first_offset=1,
    )
    mckinsey_axis = next(iter(scenario_axes))
    if penman_axis != mckinsey_axis[: len(penman_axis)]:
        raise FinalRequestCompilationError("McKinsey and Penman forecast axes differ")
    annual_axis(
        list(penman_payload["market_challenge_path"]),
        "Penman challenge",
        first_offset=len(penman_axis) + 1,
    )


def _compile_from_artifact(
    *,
    prepared: PreparedMarketReference,
    artifact: dict[str, Any],
    kernel_repository: Path,
) -> FinalValuationRequestCompilationResult:
    """Compile from a replayed artifact; kept internal for deterministic tests."""

    kernel, schemas = _verify_kernel(kernel_repository)
    snapshot = prepared.snapshot
    if (
        artifact["issuer_id"] != snapshot.issuer_id
        or artifact["data_cutoff_date"] != snapshot.data_cutoff_date
        or artifact["price_blind_input_fingerprint"]
        != snapshot.price_blind_input_fingerprint
        or artifact["protected_mckinsey_sha256"]
        != snapshot.protected_mckinsey_sha256
        or artifact["protected_penman_assumptions_sha256"]
        != snapshot.protected_penman_assumptions_sha256
        or artifact["component_lock_sha256"] != snapshot.component_lock_sha256
    ):
        raise FinalRequestCompilationError("prepared market reference changed the frozen input")
    identity = artifact["kernel_identity"]
    if (
        identity["tag"] != PINNED_KERNEL_TAG
        or identity["commit"] != PINNED_KERNEL_COMMIT
        or identity["public_schema_sha256"] != PINNED_KERNEL_SCHEMA_SHA256
    ):
        raise FinalRequestCompilationError("price-blind artifact does not bind pinned rc.2")
    reviewed = artifact["reviewed_assumptions"]
    base_ledger = to_json_value(reviewed["augmented_fact_ledger_payload"])
    base_assumptions = to_json_value(reviewed["assumption_ledger_payload"])
    if (
        canonical_sha256(base_ledger) != base_assumptions["fact_ledger_fingerprint"]
        or canonical_sha256(base_assumptions["assumptions"])
        != reviewed["assumption_entries_sha256"]
    ):
        raise FinalRequestCompilationError("price-blind ledgers do not replay")
    fact_result = _compile_fact_ledger(base_ledger=base_ledger, prepared=prepared)
    final_ledger = to_json_value(fact_result.fact_ledger_payload)
    assumption_result = _compile_assumption_ledger(base_assumptions, final_ledger)
    final_assumptions = to_json_value(assumption_result.assumption_ledger_payload)
    phase5c = to_json_value(artifact["phase5c_readiness"])
    mckinsey = to_json_value(artifact["mckinsey_inputs"])
    penman = to_json_value(artifact["penman_inputs"])
    current_fact_id = fact_result.current_share_projection.current_share_fact_id
    market_fact_id = next(
        fact_id
        for fact_id in fact_result.added_fact_ids
        if fact_id.startswith("derived:")
        and next(item for item in final_ledger["facts"] if item["fact_id"] == fact_id)[
            "concept"
        ]
        == "market_equity_value"
    )
    bridge = phase5c["equity_bridge_result"]
    _validate_forecast_axis(
        valuation_date=final_ledger["valuation_date"],
        mckinsey_scenarios=mckinsey["scenario_payload"]["scenarios"],
        penman_payload=penman["penman_payload"],
    )
    request = {
        "schema_version": "2.0.0",
        "model_unit": f"{final_ledger['reporting_currency']} millions",
        "share_unit": _MODEL_SHARE_UNIT,
        "fact_ledger": final_ledger,
        "assumption_ledger": final_assumptions,
        "company": _request_company(phase5c, prepared),
        "routing_assessments": _request_routing(phase5c, final_assumptions),
        "accounting_checks": _request_accounting(phase5c, final_ledger),
        "method_views": _request_method_views(phase5c),
        "mckinsey": {
            "base_invested_capital_fact_id": mckinsey[
                "base_invested_capital_fact_id"
            ],
            "scenarios": mckinsey["scenario_payload"]["scenarios"],
            "equity_bridge": {
                "share_denominator_fact_id": current_fact_id,
                "share_denominator_kind": "current_common_shares_outstanding",
                "share_denominator_evidence_kind": (
                    fact_result.current_share_projection.evidence_kind
                ),
                "items": bridge["bridge_items"],
                "role_assertions": bridge["role_assertions"],
            },
        },
        "penman": {
            "current_noa_fact_id": penman["current_noa_fact_id"],
            "market_equity_value_fact_id": market_fact_id,
            "net_financial_obligations_fact_id": penman[
                "net_financial_obligations_fact_id"
            ],
            **penman["penman_payload"],
        },
    }
    if request["mckinsey"]["equity_bridge"]["share_denominator_fact_id"] != next(
        item["parent_fact_ids"][1]
        for item in final_ledger["facts"]
        if item["fact_id"] == market_fact_id
    ):
        raise FinalRequestCompilationError("McKinsey and Penman use different share Facts")
    _validate_request_schema(request, schemas)
    _runtime_ledger_preflight(kernel, request)
    return FinalValuationRequestCompilationResult(
        status="compiled",
        issuer_id=snapshot.issuer_id,
        valuation_date=snapshot.trading_date,
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        prepared_market_reference_fingerprint=prepared.fingerprint,
        fact_ledger_result=fact_result,
        assumption_ledger_result=assumption_result,
        request_payload=freeze(request),
        canonical_request_json=canonical_json(request),
        request_sha256=canonical_sha256(request),
        issue_codes=(),
    )


def compile_final_valuation_request(
    *,
    preparation: OwnerValuationPreparationResult,
    expected_freeze: PriceBlindFreezeCompilationResult,
    kernel_repository: Path,
) -> FinalValuationRequestCompilationResult:
    """Compile a complete rc.2 request from one replayed price-blind/market pair."""

    if preparation.status != "prepared" or preparation.prepared_market_reference is None:
        return _noncompiled(
            preparation=preparation,
            status=(
                "specialist_required"
                if preparation.status == "specialist_required"
                else "blocked"
            ),
            issue="preparation_not_ready",
        )
    artifact = expected_freeze.artifact.to_dict()
    prepared = preparation.prepared_market_reference
    if (
        preparation.issuer_id != artifact["issuer_id"]
        or preparation.data_cutoff_date != artifact["data_cutoff_date"]
        or preparation.price_blind_input_fingerprint
        != artifact["price_blind_input_fingerprint"]
        or prepared.snapshot.authorization_handoff_id
        != expected_freeze.handoffs[-1].handoff_id
        or prepared.snapshot.authorization_handoff_fingerprint
        != expected_freeze.handoffs[-1].fingerprint
    ):
        return _noncompiled(
            preparation=preparation,
            status="blocked",
            issue="freeze_or_authorization_binding_mismatch",
        )
    try:
        return _compile_from_artifact(
            prepared=prepared,
            artifact=artifact,
            kernel_repository=kernel_repository,
        )
    except (FinalRequestCompilationError, InvalidOperation, KeyError, ValueError) as exc:
        return _noncompiled(
            preparation=preparation,
            status="blocked",
            issue=f"final_request_blocked:{type(exc).__name__}",
        )


__all__ = ()
