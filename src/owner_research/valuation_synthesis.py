"""Deterministic three-panel valuation synthesis with retained exact authority."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from .contracts import Contract, MarketReferenceSnapshot
from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .futu_session import FutuPeerEvidenceSet, validate_futu_peer_evidence_set
from .research_bundle_validation import GRAPH_DOMAIN_TYPES
from .validation import ContractGraph
from .valuation_run import ValuationRunResult, _replay_retained_completed_run
from .valuation_run_archive import ValuationRunArchive
from .valuation_synthesis_types import (
    ComparableInputReceipt,
    ComparableValuationResult,
    CompositeValuationResult,
    ExtensionContract,
    ForwardReOIInputReceipt,
    ForwardReOIValuationResult,
    NamedHumanReviewAuthority,
    ValuationBasisReceipt,
    _graph_fingerprint,
    _graph_object_id,
    _object_fingerprint,
    extension_decimal_in_domain,
    replay_retained_completed_run_once,
    retained_authority_replay_scope,
    validate_extension_payload,
)

_SCENARIOS = ("black_swan", "base", "bull")
_KERNEL_SCENARIOS = ("black_swan", "bear", "base", "bull")
_COMPARABLE_METRICS = frozenset({"price_earnings", "price_fcf"})
_METRIC_FACT_CONCEPTS = {
    "price_earnings": frozenset({"net_income", "net_income_loss"}),
    "price_fcf": frozenset({"free_cash_flow"}),
}
_SUPPORTED_UNIT_PAIRS = frozenset(
    {("USD", "shares"), ("USD millions", "millions shares")}
)
_DISPERSION_LIMIT = Decimal("0.50")
_BINARY64_REPLAY_TOLERANCE = Decimal("1e-12")
_CALCULATION_PRECISION = 60
_VALUATION_DECIMAL_CONTEXT = Context(
    prec=_CALCULATION_PRECISION,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[InvalidOperation, DivisionByZero, Overflow],
)
_CURRENT_COMPARABLE_MAX_AGE_DAYS = 456
_CURRENT_COMPARABLE_DURATION_DAYS = frozenset({364, 365, 366, 371})
_PEER_SELECTION_FIELDS = frozenset(
    {
        "peer_id",
        "company_name",
        "issuer_id",
        "security_id",
        "ticker",
        "listing_mic",
        "currency",
        "fact_bindings",
    }
)
_BINDING_FIELDS = frozenset({"object_type", "object_id", "fingerprint"})
_P = ParamSpec("_P")
_R = TypeVar("_R")


class ValuationSynthesisError(ValueError):
    """A downstream panel lacks closed, mutually consistent authority."""


def _valuation_decimal_scope(function: Callable[_P, _R]) -> Callable[_P, _R]:
    """Run one valuation entry or replay under the complete fixed context."""

    @wraps(function)
    def scoped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with localcontext(_VALUATION_DECIMAL_CONTEXT):
            return function(*args, **kwargs)

    return scoped


def _decimal(value: object, label: str) -> Decimal:
    if isinstance(value, bool):
        raise ValuationSynthesisError(f"{label} must be a finite decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValuationSynthesisError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValuationSynthesisError(f"{label} must be a finite decimal")
    if not extension_decimal_in_domain(parsed):
        raise ValuationSynthesisError(f"{label} exceeds the bounded decimal domain")
    return parsed


def _positive(value: object, label: str) -> Decimal:
    parsed = _decimal(value, label)
    if parsed <= 0:
        raise ValuationSynthesisError(f"{label} must be positive")
    return parsed


def _nonnegative(value: object, label: str) -> Decimal:
    parsed = _decimal(value, label)
    if parsed < 0:
        raise ValuationSynthesisError(f"{label} cannot be negative")
    return parsed


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise ValuationSynthesisError("non-finite decimal cannot be serialized")
    if value == 0:
        return "0"
    rendered = format(value, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _same_decimal(left: Decimal, right: Decimal) -> bool:
    with localcontext(_VALUATION_DECIMAL_CONTEXT):
        return abs(left - right) <= max(abs(left), abs(right), Decimal(1)) * (
            _BINARY64_REPLAY_TOLERANCE
        )


def _median(values: Sequence[Decimal]) -> Decimal:
    ordered = sorted(values)
    if not ordered:
        raise ValuationSynthesisError("median requires at least one value")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    with localcontext(_VALUATION_DECIMAL_CONTEXT):
        return (ordered[middle - 1] + ordered[middle]) / Decimal(2)


def _timestamp(value: object, label: str) -> str:
    if type(value) is not str:
        raise ValuationSynthesisError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValuationSynthesisError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValuationSynthesisError(f"{label} must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _one_year_later(value: str) -> str:
    current = date.fromisoformat(value)
    try:
        return current.replace(year=current.year + 1).isoformat()
    except ValueError:
        return current.replace(year=current.year + 1, day=28).isoformat()


def _seal(prefix: str, issuer_id: str, payload: dict[str, Any], field_name: str) -> dict[str, Any]:
    payload[field_name] = f"{prefix}:{issuer_id}:{canonical_sha256(payload)[:24]}"
    return payload


def _completed_run(
    run_result: object,
) -> tuple[ValuationRunResult, ValuationRunArchive, dict[str, Any], dict[str, Any]]:
    if type(run_result) is not ValuationRunResult or run_result.status != "completed":
        raise ValuationSynthesisError(
            "synthesis requires an exact completed ValuationRunResult"
        )
    try:
        archive, request, result = replay_retained_completed_run_once(
            run_result,
            _replay_retained_completed_run,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValuationSynthesisError(
            "completed valuation run retained authority no longer replays"
        ) from exc
    if (
        type(archive) is not ValuationRunArchive
        or not isinstance(request, dict)
        or not isinstance(result, dict)
    ):
        raise ValuationSynthesisError(
            "completed valuation run retained replay returned invalid typed outputs"
        )
    return run_result, archive, request, result


def _review(
    run_result: ValuationRunResult,
    authority: object,
    *,
    scope: str,
) -> NamedHumanReviewAuthority:
    if type(authority) is not NamedHumanReviewAuthority:
        raise ValuationSynthesisError(f"{scope} requires exact named-human review authority")
    try:
        authority.__post_init__()
    except (OSError, TypeError, ValueError) as exc:
        raise ValuationSynthesisError(f"{scope} review authority does not replay") from exc
    if (
        authority.scope != scope
        or authority.issuer_id != run_result.issuer_id
        or authority.data_cutoff_date != run_result.data_cutoff_date
        or authority.graph != run_result.input_receipt.graph
        or authority.research_bundle not in run_result.input_receipt.graph.research_bundles
        or _graph_fingerprint(authority.graph) != run_result.input_receipt.graph_fingerprint
    ):
        raise ValuationSynthesisError(f"{scope} review is bound to another run or bundle")
    return authority


def _evidence_ids(authority: NamedHumanReviewAuthority) -> tuple[str, ...]:
    return tuple(sorted(item["object_id"] for item in authority.evidence_bindings))


def _fact_value(request: Mapping[str, Any], fact_id: str, label: str) -> Decimal:
    facts = request.get("fact_ledger", {}).get("facts", [])
    matches = [item for item in facts if item.get("fact_id") == fact_id]
    if len(matches) != 1:
        raise ValuationSynthesisError(f"{label} does not resolve to one kernel Fact")
    return _decimal(matches[0].get("value"), label)


def _mckinsey_scenarios(result: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    panel = result.get("panels", {}).get("mckinsey")
    if not isinstance(panel, dict) or not isinstance(panel.get("scenarios"), list):
        raise ValuationSynthesisError("completed kernel result lacks the McKinsey panel")
    by_name: dict[str, dict[str, Any]] = {}
    for row in panel["scenarios"]:
        if not isinstance(row, dict) or row.get("name") not in _KERNEL_SCENARIOS:
            raise ValuationSynthesisError("McKinsey scenario shape is invalid")
        if row["name"] in by_name:
            raise ValuationSynthesisError("McKinsey scenario is duplicated")
        by_name[row["name"]] = row
    if tuple(name for name in _KERNEL_SCENARIOS if name in by_name) != _KERNEL_SCENARIOS:
        raise ValuationSynthesisError("McKinsey panel lacks a required scenario")
    return by_name


def _snapshot_shares_in_model_unit(shares: Decimal, share_unit: str) -> Decimal:
    if share_unit == "shares":
        return shares
    if share_unit == "millions shares":
        with localcontext(_VALUATION_DECIMAL_CONTEXT):
            return shares / Decimal("1000000")
    raise ValuationSynthesisError("kernel share unit is outside v1 support")


def _basis_payload(
    run_result: ValuationRunResult,
    review_authority: NamedHumanReviewAuthority,
) -> dict[str, Any]:
    run_result, archive, request, result = _completed_run(run_result)
    review_authority = _review(run_result, review_authority, scope="valuation_basis")
    snapshot = archive.market_reference
    if type(snapshot) is not MarketReferenceSnapshot:
        raise ValuationSynthesisError("valuation basis requires the typed market Snapshot")
    reviewed = to_json_value(review_authority.reviewed_payload)
    required = {
        "twelve_month_shares",
        "current_net_financial_obligations_fact_id",
        "twelve_month_nonoperating_assets",
        "twelve_month_nonequity_claims",
        "twelve_month_net_financial_obligations",
    }
    if not isinstance(reviewed, dict) or set(reviewed) != required:
        raise ValuationSynthesisError("valuation-basis reviewed payload fields are not closed")
    if (
        snapshot.quote_currency != "USD"
        or snapshot.security["mic"] not in {"XNYS", "XNAS"}
        or snapshot.security["share_class"] != "common"
    ):
        raise ValuationSynthesisError("v1 synthesis supports one XNYS/XNAS USD common share")
    nfo_fact_id = reviewed["current_net_financial_obligations_fact_id"]
    if type(nfo_fact_id) is not str or not nfo_fact_id:
        raise ValuationSynthesisError("basis review lacks current NFO Fact authority")
    governed_nfo_id = request.get("penman", {}).get("net_financial_obligations_fact_id")
    if governed_nfo_id is not None and governed_nfo_id != nfo_fact_id:
        raise ValuationSynthesisError("basis review changed the governed current NFO Fact")
    facts_by_id = {
        item.get("fact_id"): item
        for item in request.get("fact_ledger", {}).get("facts", [])
        if isinstance(item, Mapping)
    }
    share_fact_id = request.get("mckinsey", {}).get("equity_bridge", {}).get(
        "share_denominator_fact_id"
    )
    model_unit = request.get("model_unit") or facts_by_id.get(nfo_fact_id, {}).get("unit")
    share_unit = request.get("share_unit") or facts_by_id.get(share_fact_id, {}).get("unit")
    if (model_unit, share_unit) not in _SUPPORTED_UNIT_PAIRS:
        raise ValuationSynthesisError("kernel currency/share units are outside v1 support")
    by_name = _mckinsey_scenarios(result)
    denominators: set[Decimal] = set()
    assets: set[Decimal] = set()
    claims: set[Decimal] = set()
    for name in _SCENARIOS:
        bridge = by_name[name].get("equity_bridge")
        if (
            not isinstance(bridge, dict)
            or bridge.get("share_denominator_kind")
            != "current_common_shares_outstanding"
            or not bridge.get("share_denominator_evidence_kind")
        ):
            raise ValuationSynthesisError("McKinsey scenario lacks current-share authority")
        denominators.add(_positive(bridge.get("share_denominator"), "current shares"))
        assets.add(_nonnegative(bridge.get("nonoperating_assets"), "current assets"))
        claims.add(_nonnegative(bridge.get("nonequity_claims"), "current claims"))
    if len(denominators) != 1 or len(assets) != 1 or len(claims) != 1:
        raise ValuationSynthesisError("McKinsey scenarios use different equity bridges")
    current_shares = next(iter(denominators))
    current_assets = next(iter(assets))
    current_claims = next(iter(claims))
    snapshot_shares = _positive(
        snapshot.share_basis["current_common_shares_outstanding_decimal"],
        "Snapshot current shares",
    )
    if not _same_decimal(
        _snapshot_shares_in_model_unit(snapshot_shares, share_unit),
        current_shares,
    ):
        raise ValuationSynthesisError("kernel and market current-share bases differ")
    current_nfo = _fact_value(request, nfo_fact_id, "current NFO")
    if not _same_decimal(current_nfo, current_claims - current_assets):
        raise ValuationSynthesisError("McKinsey and Penman current equity bridges differ")
    future_shares = _positive(reviewed["twelve_month_shares"], "twelve-month shares")
    future_assets = _nonnegative(
        reviewed["twelve_month_nonoperating_assets"], "twelve-month assets"
    )
    future_claims = _nonnegative(
        reviewed["twelve_month_nonequity_claims"], "twelve-month claims"
    )
    future_nfo = _decimal(
        reviewed["twelve_month_net_financial_obligations"], "twelve-month NFO"
    )
    if future_nfo != future_claims - future_assets:
        raise ValuationSynthesisError("twelve-month equity bridge does not reconcile")
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "issuer_id": snapshot.issuer_id,
        "security_id": snapshot.security["security_id"],
        "ticker": snapshot.security["ticker"],
        "listing_mic": snapshot.security["mic"],
        "share_class": snapshot.security["share_class"],
        "currency": snapshot.quote_currency,
        "model_unit": model_unit,
        "share_unit": share_unit,
        "valuation_date": snapshot.data_cutoff_date,
        "twelve_month_date": _one_year_later(snapshot.data_cutoff_date),
        "current_shares": _decimal_text(current_shares),
        "twelve_month_shares": _decimal_text(future_shares),
        "current_nonoperating_assets": _decimal_text(current_assets),
        "current_nonequity_claims": _decimal_text(current_claims),
        "current_net_financial_obligations_fact_id": nfo_fact_id,
        "current_net_financial_obligations": _decimal_text(current_nfo),
        "twelve_month_nonoperating_assets": _decimal_text(future_assets),
        "twelve_month_nonequity_claims": _decimal_text(future_claims),
        "twelve_month_net_financial_obligations": _decimal_text(future_nfo),
        "core_archive_fingerprint": archive.fingerprint,
        "core_result_sha256": archive.manifest["valuation_result_sha256"],
        "run_input_receipt_fingerprint": run_result.input_receipt.fingerprint,
        "price_blind_input_fingerprint": snapshot.price_blind_input_fingerprint,
        "market_reference_snapshot_fingerprint": snapshot.fingerprint,
        "share_basis_decision_fingerprint": snapshot.share_basis["decision_fingerprint"],
        "review_authority_fingerprint": review_authority.fingerprint,
        "reviewer_id": review_authority.reviewer_id,
        "reviewed_at": review_authority.reviewed_at,
        "evidence_ids": _evidence_ids(review_authority),
    }
    return _seal("valuation-basis-receipt", snapshot.issuer_id, payload, "receipt_id")


@retained_authority_replay_scope
@_valuation_decimal_scope
def build_valuation_basis_receipt(
    run_result: ValuationRunResult,
    *,
    review_authority: NamedHumanReviewAuthority,
) -> ValuationBasisReceipt:
    """Build the common basis only from a strict run and exact typed review."""

    return ValuationBasisReceipt(
        **_basis_payload(run_result, review_authority),
        _run_result=run_result,
        _review_authority=review_authority,
    )


def _normalized_reoi_scenarios(
    value: object,
    *,
    valuation_date: str,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) != 3:
        raise ValuationSynthesisError("forward ReOI requires exactly three scenarios")
    normalized: dict[str, dict[str, Any]] = {}
    common_axis: tuple[str, ...] | None = None
    for supplied in value:
        if not isinstance(supplied, Mapping) or set(supplied) != {
            "name",
            "hurdle_rate",
            "terminal_growth",
            "forecast",
        }:
            raise ValuationSynthesisError("forward ReOI scenario fields are not closed")
        name = supplied["name"]
        if name not in _SCENARIOS or name in normalized:
            raise ValuationSynthesisError("forward ReOI scenario names are not closed")
        hurdle = _positive(supplied["hurdle_rate"], f"{name} hurdle rate")
        growth = _decimal(supplied["terminal_growth"], f"{name} terminal growth")
        if hurdle >= 1 or growth <= -1 or growth >= hurdle:
            raise ValuationSynthesisError("forward ReOI terminal economics are invalid")
        forecast = supplied["forecast"]
        if (
            not isinstance(forecast, Sequence)
            or isinstance(forecast, (str, bytes))
            or not 2 <= len(forecast) <= 30
        ):
            raise ValuationSynthesisError("forward ReOI requires two to thirty forecast years")
        previous = date.fromisoformat(valuation_date)
        rows: list[dict[str, str]] = []
        axis: list[str] = []
        for row in forecast:
            if not isinstance(row, Mapping) or set(row) != {
                "period_end",
                "operating_income_after_tax",
                "ending_noa",
            }:
                raise ValuationSynthesisError("forward ReOI forecast fields are not closed")
            try:
                period_end = date.fromisoformat(str(row["period_end"]))
            except ValueError as exc:
                raise ValuationSynthesisError("forward ReOI period is invalid") from exc
            if not 360 <= (period_end - previous).days <= 373:
                raise ValuationSynthesisError("forward ReOI periods must be sequential annual rows")
            previous = period_end
            rows.append(
                {
                    "period_end": period_end.isoformat(),
                    "operating_income_after_tax": _decimal_text(
                        _decimal(row["operating_income_after_tax"], f"{name} operating income")
                    ),
                    "ending_noa": _decimal_text(
                        _positive(row["ending_noa"], f"{name} ending NOA")
                    ),
                }
            )
            axis.append(period_end.isoformat())
        if common_axis is None:
            common_axis = tuple(axis)
        elif tuple(axis) != common_axis:
            raise ValuationSynthesisError("forward ReOI scenarios must share one annual axis")
        normalized[name] = {
            "name": name,
            "hurdle_rate": _decimal_text(hurdle),
            "terminal_growth": _decimal_text(growth),
            "forecast": rows,
        }
    if set(normalized) != set(_SCENARIOS):
        raise ValuationSynthesisError("forward ReOI requires base, bull, and black-swan")
    return tuple(normalized[name] for name in _SCENARIOS)


def _basis_replay(
    run_result: ValuationRunResult,
    basis: object,
) -> ValuationBasisReceipt:
    if type(basis) is not ValuationBasisReceipt:
        raise ValuationSynthesisError("synthesis requires the exact common-basis receipt")
    try:
        basis.__post_init__()
    except (OSError, TypeError, ValueError) as exc:
        raise ValuationSynthesisError("common-basis receipt does not replay") from exc
    if basis._run_result != run_result:
        raise ValuationSynthesisError("common basis is bound to another valuation run")
    return basis


def _forward_input_payload(
    run_result: ValuationRunResult,
    basis: ValuationBasisReceipt,
    review_authority: NamedHumanReviewAuthority,
) -> dict[str, Any]:
    run_result, _archive, request, result = _completed_run(run_result)
    basis = _basis_replay(run_result, basis)
    review_authority = _review(run_result, review_authority, scope="forward_reoi")
    reviewed = to_json_value(review_authority.reviewed_payload)
    if not isinstance(reviewed, dict) or set(reviewed) != {
        "current_noa_fact_id",
        "scenarios",
    }:
        raise ValuationSynthesisError("forward ReOI reviewed payload fields are not closed")
    try:
        penman = request["penman"]
    except (KeyError, TypeError) as exc:
        raise ValuationSynthesisError("kernel request lacks price-blind Penman authority") from exc
    current_noa_id = reviewed["current_noa_fact_id"]
    current_nfo_id = basis.current_net_financial_obligations_fact_id
    if type(current_noa_id) is not str or not current_noa_id:
        raise ValuationSynthesisError("forward ReOI review lacks current NOA Fact authority")
    governed_noa_id = penman.get("current_noa_fact_id")
    if governed_noa_id is not None and governed_noa_id != current_noa_id:
        raise ValuationSynthesisError("forward review changed the governed current NOA Fact")
    current_noa = _positive(_fact_value(request, current_noa_id, "current NOA"), "current NOA")
    current_nfo = _fact_value(request, current_nfo_id, "current NFO")
    if current_nfo != _decimal(basis.current_net_financial_obligations, "basis current NFO"):
        raise ValuationSynthesisError("forward ReOI current equity bridge drifted")
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "issuer_id": basis.issuer_id,
        "valuation_date": basis.valuation_date,
        "basis_receipt_fingerprint": basis.fingerprint,
        "run_input_receipt_fingerprint": run_result.input_receipt.fingerprint,
        "price_blind_input_fingerprint": basis.price_blind_input_fingerprint,
        "assumption_ledger_fingerprint": result["assumption_ledger_fingerprint"],
        "current_noa_fact_id": current_noa_id,
        "current_noa": _decimal_text(current_noa),
        "current_nfo_fact_id": current_nfo_id,
        "current_nfo": _decimal_text(current_nfo),
        "scenarios": _normalized_reoi_scenarios(
            reviewed["scenarios"], valuation_date=basis.valuation_date
        ),
        "review_authority_fingerprint": review_authority.fingerprint,
        "reviewer_id": review_authority.reviewer_id,
        "reviewed_at": review_authority.reviewed_at,
        "evidence_ids": _evidence_ids(review_authority),
    }
    return _seal("forward-reoi-input-receipt", basis.issuer_id, payload, "receipt_id")


def _forward_result_payload(
    run_result: ValuationRunResult,
    basis: ValuationBasisReceipt,
    input_receipt: ForwardReOIInputReceipt,
) -> dict[str, Any]:
    _completed_run(run_result)
    basis = _basis_replay(run_result, basis)
    if (
        type(input_receipt) is not ForwardReOIInputReceipt
        or input_receipt._run_result != run_result
        or input_receipt._basis_authority != basis
    ):
        raise ValuationSynthesisError("forward ReOI input authority changed")
    current_noa = _positive(input_receipt.current_noa, "current NOA")
    current_nfo = _decimal(input_receipt.current_nfo, "current NFO")
    current_shares = _positive(basis.current_shares, "current shares")
    future_shares = _positive(basis.twelve_month_shares, "twelve-month shares")
    future_nfo = _decimal(basis.twelve_month_net_financial_obligations, "twelve-month NFO")
    scenario_results: list[dict[str, Any]] = []
    with localcontext(_VALUATION_DECIMAL_CONTEXT):
        for scenario in input_receipt.scenarios:
            hurdle = _positive(scenario["hurdle_rate"], "forward ReOI hurdle")
            growth = _decimal(scenario["terminal_growth"], "forward ReOI growth")
            discount = Decimal(1) + hurdle
            noa_start = current_noa
            residuals: list[Decimal] = []
            noa_ends: list[Decimal] = []
            for row in scenario["forecast"]:
                noa_end = _positive(row["ending_noa"], "forward ending NOA")
                residuals.append(
                    _decimal(row["operating_income_after_tax"], "forward income")
                    - hurdle * noa_start
                )
                noa_ends.append(noa_end)
                noa_start = noa_end
            terminal_reoi = residuals[-1] * (Decimal(1) + growth)
            terminal_at_horizon = terminal_reoi / (hurdle - growth)
            current_operating = (
                current_noa
                + sum(
                    (value / (discount**year) for year, value in enumerate(residuals, 1)),
                    Decimal(0),
                )
                + terminal_at_horizon / (discount ** len(residuals))
            )
            twelve_month_operating = (
                noa_ends[0]
                + sum(
                    (value / (discount**year) for year, value in enumerate(residuals[1:], 1)),
                    Decimal(0),
                )
                + terminal_at_horizon / (discount ** (len(residuals) - 1))
            )
            current_equity = current_operating - current_nfo
            future_equity = twelve_month_operating - future_nfo
            current_per_share = current_equity / current_shares
            future_per_share = future_equity / future_shares
            if current_per_share <= 0 or future_per_share <= 0:
                raise ValuationSynthesisError("forward ReOI produces nonpositive per-share value")
            scenario_results.append(
                {
                    "name": scenario["name"],
                    "method_label": "PROJECT_EXTENSION_PENMAN_FORWARD_REOI",
                    "residual_operating_incomes": [
                        _decimal_text(value) for value in residuals
                    ],
                    "terminal_reoi_next": _decimal_text(terminal_reoi),
                    "current_operating_value": _decimal_text(current_operating),
                    "current_equity_value": _decimal_text(current_equity),
                    "current_value_per_share": _decimal_text(current_per_share),
                    "twelve_month_operating_value": _decimal_text(twelve_month_operating),
                    "twelve_month_equity_value": _decimal_text(future_equity),
                    "twelve_month_value_per_share": _decimal_text(future_per_share),
                }
            )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "extension_label": "PROJECT_EXTENSION_PENMAN_FORWARD_REOI",
        "status": "complete",
        "issuer_id": basis.issuer_id,
        "basis_receipt": basis.to_dict(),
        "input_receipt": input_receipt.to_dict(),
        "scenarios": scenario_results,
        "issue_codes": (),
    }
    return _seal("forward-reoi-result", basis.issuer_id, payload, "result_id")


@retained_authority_replay_scope
@_valuation_decimal_scope
def build_forward_reoi_valuation(
    run_result: ValuationRunResult,
    *,
    basis_receipt: ValuationBasisReceipt,
    review_authority: NamedHumanReviewAuthority,
) -> ForwardReOIValuationResult:
    input_receipt = ForwardReOIInputReceipt(
        **_forward_input_payload(run_result, basis_receipt, review_authority),
        _run_result=run_result,
        _basis_authority=basis_receipt,
        _review_authority=review_authority,
    )
    return ForwardReOIValuationResult(
        **_forward_result_payload(run_result, basis_receipt, input_receipt),
        _run_result=run_result,
        _basis_authority=basis_receipt,
        _input_authority=input_receipt,
    )


def _graph_registry(graph: ContractGraph) -> dict[str, tuple[str, Contract]]:
    registry: dict[str, tuple[str, Contract]] = {}
    for graph_field, object_type in GRAPH_DOMAIN_TYPES.items():
        for item in getattr(graph, graph_field):
            identifier = _graph_object_id(graph_field, item)
            if identifier in registry:
                raise ValuationSynthesisError("peer graph object identity is duplicated")
            registry[identifier] = (object_type, item)
    return registry


def _peer_fact_binding(
    value: object,
    *,
    peer_issuer_id: str,
    registry: Mapping[str, tuple[str, Contract]],
    data_cutoff_date: str,
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _BINDING_FIELDS:
        raise ValuationSynthesisError("peer Fact binding fields are not closed")
    object_id = value["object_id"]
    resolved = registry.get(object_id) if type(object_id) is str else None
    if resolved is None or resolved[0] != "Fact" or value["object_type"] != "Fact":
        raise ValuationSynthesisError("peer evidence must resolve to an exact Fact")
    fact = resolved[1]
    if (
        getattr(fact, "issuer_id", None) != peer_issuer_id
        or value["fingerprint"] != _object_fingerprint(fact)
    ):
        raise ValuationSynthesisError("peer Fact binding identity does not replay")
    source = registry.get(getattr(fact, "source_document_id", None))
    if (
        source is None
        or source[0] != "SourceDocument"
        or getattr(source[1], "issuer_id", None) != peer_issuer_id
        or getattr(source[1], "authority_level", None)
        not in {"primary_regulatory", "company_primary"}
    ):
        raise ValuationSynthesisError("peer Fact is not backed by SEC/IR authority")
    fact_period_end = getattr(fact, "period", {}).get("end")
    if (
        getattr(source[1], "published_date", None) > data_cutoff_date
        or type(fact_period_end) is not str
        or fact_period_end > data_cutoff_date
    ):
        raise ValuationSynthesisError("peer Fact was unavailable at the research cutoff")
    return {
        "object_type": "Fact",
        "object_id": object_id,
        "fingerprint": value["fingerprint"],
    }


def _duration_period(value: object) -> tuple[date, date] | None:
    period = getattr(value, "period", None)
    if not isinstance(period, Mapping):
        return None
    start_value = period.get("start")
    end_value = period.get("end")
    if type(start_value) is not str or type(end_value) is not str:
        return None
    try:
        start = date.fromisoformat(start_value)
        end = date.fromisoformat(end_value)
    except ValueError:
        return None
    if start > end:
        return None
    return start, end


def _eligible_current_measure_period(
    value: object,
    *,
    valuation_date: date,
) -> tuple[date, date] | None:
    period = _duration_period(value)
    if period is None:
        return None
    start, end = period
    duration_days = (end - start).days + 1
    age_days = (valuation_date - end).days
    if (
        duration_days not in _CURRENT_COMPARABLE_DURATION_DAYS
        or age_days < 0
        or age_days > _CURRENT_COMPARABLE_MAX_AGE_DAYS
    ):
        return None
    return period


def _reviewed_current_fact_candidates(
    *,
    reviewed_ids: set[str],
    registry: Mapping[str, tuple[str, Contract]],
    concepts: frozenset[str],
    unit: str,
    currency: str | None,
    valuation_date: date,
) -> tuple[tuple[str, object, tuple[date, date], tuple[date, date]], ...]:
    candidates: list[tuple[str, object, tuple[date, date], tuple[date, date]]] = []
    for fact_id in reviewed_ids:
        resolved = registry.get(fact_id)
        if resolved is None or resolved[0] != "Fact":
            continue
        fact = resolved[1]
        period = _eligible_current_measure_period(fact, valuation_date=valuation_date)
        source = registry.get(getattr(fact, "source_document_id", None))
        if (
            getattr(fact, "concept", None) not in concepts
            or getattr(fact, "value_type", None) != "number"
            or getattr(fact, "unit", None) != unit
            or getattr(fact, "currency", None) != currency
            or period is None
            or source is None
            or source[0] != "SourceDocument"
        ):
            continue
        try:
            published = date.fromisoformat(source[1].published_date)
        except (AttributeError, TypeError, ValueError):
            continue
        candidates.append((fact_id, fact, period, (period[1], published)))
    return tuple(candidates)


def _require_latest_uncontested_fact(
    *,
    candidates: tuple[
        tuple[str, object, tuple[date, date], tuple[date, date]], ...
    ],
    selected_fact_id: object,
) -> None:
    if not candidates:
        raise ValuationSynthesisError(
            "peer multiple operands do not have registered SEC/IR semantics"
        )
    latest_key = max(candidate[3] for candidate in candidates)
    latest = tuple(candidate for candidate in candidates if candidate[3] == latest_key)
    if type(selected_fact_id) is not str or selected_fact_id not in {
        candidate[0] for candidate in latest
    }:
        raise ValuationSynthesisError(
            "peer multiple operands do not have registered SEC/IR semantics"
        )
    signatures = {
        (
            getattr(fact, "concept", None),
            _decimal(getattr(fact, "value", None), "peer current reviewed Fact"),
            getattr(fact, "unit", None),
            getattr(fact, "currency", None),
            period[0],
            period[1],
            getattr(fact, "derivation", None),
            tuple(getattr(fact, "parent_fact_ids", ())),
        )
        for _fact_id, fact, period, _key in latest
    }
    if len(signatures) != 1:
        raise ValuationSynthesisError(
            "peer multiple operands do not have registered SEC/IR semantics"
        )


def _require_current_comparable_period_policy(
    *,
    metric: str,
    peer: Mapping[str, Any],
    registry: Mapping[str, tuple[str, Contract]],
    measure_fact: object,
    share_fact: object,
    valuation_date: str,
) -> None:
    try:
        as_of = date.fromisoformat(valuation_date)
    except (TypeError, ValueError) as exc:
        raise ValuationSynthesisError(
            "peer multiple operands do not have registered SEC/IR semantics"
        ) from exc
    measure_period = _eligible_current_measure_period(
        measure_fact,
        valuation_date=as_of,
    )
    share_period = _duration_period(share_fact)
    if (
        measure_period is None
        or getattr(share_fact, "concept", None) != "weighted_average_diluted_shares"
        or share_period != measure_period
    ):
        raise ValuationSynthesisError(
            "peer multiple operands do not have registered SEC/IR semantics"
        )

    reviewed_ids = {
        binding["object_id"]
        for binding in peer["fact_bindings"]
        if binding["object_type"] == "Fact"
    }
    reviewed_ids.update(
        {
            getattr(measure_fact, "fact_id", ""),
            getattr(share_fact, "fact_id", ""),
        }
    )
    _require_latest_uncontested_fact(
        candidates=_reviewed_current_fact_candidates(
            reviewed_ids=reviewed_ids,
            registry=registry,
            concepts=_METRIC_FACT_CONCEPTS[metric],
            unit="currency_units",
            currency="USD",
            valuation_date=as_of,
        ),
        selected_fact_id=getattr(measure_fact, "fact_id", None),
    )
    _require_latest_uncontested_fact(
        candidates=_reviewed_current_fact_candidates(
            reviewed_ids=reviewed_ids,
            registry=registry,
            concepts=frozenset({"weighted_average_diluted_shares"}),
            unit="shares",
            currency=None,
            valuation_date=as_of,
        ),
        selected_fact_id=getattr(share_fact, "fact_id", None),
    )


def _binding_tuple(
    value: object,
    *,
    peer_issuer_id: str,
    registry: Mapping[str, tuple[str, Contract]],
    data_cutoff_date: str,
) -> tuple[dict[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValuationSynthesisError("peer Fact bindings must be a sequence")
    bindings = tuple(
        _peer_fact_binding(
            item,
            peer_issuer_id=peer_issuer_id,
            registry=registry,
            data_cutoff_date=data_cutoff_date,
        )
        for item in value
    )
    if not bindings:
        raise ValuationSynthesisError("peer evidence requires at least one SEC/IR Fact")
    identities = {(item["object_id"], item["fingerprint"]) for item in bindings}
    if len(identities) != len(bindings):
        raise ValuationSynthesisError("peer Fact binding is duplicated")
    return tuple(sorted(bindings, key=lambda item: item["object_id"]))


def _normalize_peer_authority(
    *,
    run_result: ValuationRunResult,
    selection_review: NamedHumanReviewAuthority,
    forecast_review: NamedHumanReviewAuthority,
    peer_graphs: Sequence[ContractGraph],
    futu_peer_evidence_set: FutuPeerEvidenceSet,
    verifier: object,
) -> tuple[str, tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    run_result, archive, _request, _result = _completed_run(run_result)
    selection_review = _review(run_result, selection_review, scope="peer_set_selection")
    forecast_review = _review(run_result, forecast_review, scope="comparable_forecast")
    if (
        not isinstance(peer_graphs, Sequence)
        or isinstance(peer_graphs, (str, bytes))
        or not 5 <= len(peer_graphs) <= 15
        or any(type(item) is not ContractGraph for item in peer_graphs)
    ):
        raise ValuationSynthesisError(
            "peer authority requires five to fifteen exact single-issuer graphs"
        )
    registries: dict[str, dict[str, tuple[str, Contract]]] = {}
    for peer_graph in peer_graphs:
        try:
            peer_graph.validate()
        except (OSError, ValueError) as exc:
            raise ValuationSynthesisError("peer SEC/IR ContractGraph does not replay") from exc
        issuers = {
            item.issuer_id
            for graph_field in GRAPH_DOMAIN_TYPES
            for item in getattr(peer_graph, graph_field)
            if type(getattr(item, "issuer_id", None)) is str
        }
        if len(issuers) != 1:
            raise ValuationSynthesisError("each peer graph must retain one peer issuer")
        issuer_id = next(iter(issuers))
        if issuer_id in registries:
            raise ValuationSynthesisError("peer graph issuer identity is duplicated")
        registries[issuer_id] = _graph_registry(peer_graph)
    if type(futu_peer_evidence_set) is not FutuPeerEvidenceSet:
        raise ValuationSynthesisError("peer authority requires exact FutuPeerEvidenceSet")
    try:
        validate_futu_peer_evidence_set(futu_peer_evidence_set, verifier=verifier)
    except (OSError, TypeError, ValueError) as exc:
        raise ValuationSynthesisError("Futu peer evidence set does not replay") from exc
    if (
        futu_peer_evidence_set.target_security_id
        != archive.market_reference.security["security_id"]
        or futu_peer_evidence_set.price_blind_freeze
        != run_result.input_receipt.expected_freeze
        or futu_peer_evidence_set.price_blind_freeze_fingerprint
        != run_result.input_receipt.price_blind_input_fingerprint
    ):
        raise ValuationSynthesisError("Futu peer set is bound to another target or freeze")
    selection = to_json_value(selection_review.reviewed_payload)
    if not isinstance(selection, dict) or set(selection) != {
        "selection_frozen_at",
        "peers",
        "registered_metrics",
        "missing_data_policy",
    }:
        raise ValuationSynthesisError("peer-selection review fields are not closed")
    frozen_at = _timestamp(selection["selection_frozen_at"], "selection_frozen_at")
    if selection_review.reviewed_at != frozen_at:
        raise ValuationSynthesisError("peer-selection review was not frozen at its decision time")
    if datetime.fromisoformat(forecast_review.reviewed_at.replace("Z", "+00:00")) > (
        datetime.fromisoformat(frozen_at.replace("Z", "+00:00"))
    ):
        raise ValuationSynthesisError(
            "comparable forecasts were not frozen before peer selection"
        )
    if selection["missing_data_policy"] != "complete_case_all_preselected_peers":
        raise ValuationSynthesisError("peer missing-data policy permits outcome-based exclusion")
    registered_metrics = selection["registered_metrics"]
    if (
        not isinstance(registered_metrics, Sequence)
        or isinstance(registered_metrics, (str, bytes))
        or not 2 <= len(registered_metrics) <= 4
        or len(set(registered_metrics)) != len(registered_metrics)
        or any(item not in _COMPARABLE_METRICS for item in registered_metrics)
    ):
        raise ValuationSynthesisError("peer metrics were not validly pre-registered")
    selected_peers = selection["peers"]
    if (
        not isinstance(selected_peers, Sequence)
        or isinstance(selected_peers, (str, bytes))
        or not 5 <= len(selected_peers) <= 15
    ):
        raise ValuationSynthesisError("peer selection requires five to fifteen peers")
    futu_by_security = {
        item.security_id: item for item in futu_peer_evidence_set.peers
    }
    normalized_peers: list[dict[str, Any]] = []
    peer_ids: set[str] = set()
    security_ids: set[str] = set()
    for raw_peer in selected_peers:
        if not isinstance(raw_peer, Mapping) or set(raw_peer) != _PEER_SELECTION_FIELDS:
            raise ValuationSynthesisError("selected-peer fields are not closed")
        peer_id = raw_peer["peer_id"]
        issuer_id = raw_peer["issuer_id"]
        security_id = raw_peer["security_id"]
        if (
            any(type(item) is not str or not item for item in (peer_id, issuer_id, security_id))
            or peer_id in peer_ids
            or security_id in security_ids
            or security_id == futu_peer_evidence_set.target_security_id
        ):
            raise ValuationSynthesisError("selected-peer identity is duplicated or invalid")
        futu_peer = futu_by_security.get(security_id)
        registry = registries.get(issuer_id)
        security_receipt = futu_peer.authority_set.security_identity if futu_peer else None
        if futu_peer is None or futu_peer.issuer_id != issuer_id or registry is None:
            raise ValuationSynthesisError("selected peer lacks the exact Futu session")
        if (
            raw_peer["listing_mic"] not in {"XNYS", "XNAS"}
            or raw_peer["currency"] != "USD"
            or futu_peer.daily_close.currency != "USD"
            or futu_peer.daily_close.trading_date
            != archive.market_reference.trading_date
            or security_receipt is None
            or raw_peer["ticker"] != security_receipt.ticker
            or raw_peer["listing_mic"] != security_receipt.mic
        ):
            raise ValuationSynthesisError("selected peer is outside the v1 USD universe")
        if any(
            datetime.fromisoformat(
                item.request_started_at.replace("Z", "+00:00")
            )
            <= datetime.fromisoformat(frozen_at.replace("Z", "+00:00"))
            for item in futu_peer.execution.requests
        ):
            raise ValuationSynthesisError(
                "peer price or static data was read before peer selection froze"
            )
        bindings = _binding_tuple(
            raw_peer["fact_bindings"],
            peer_issuer_id=issuer_id,
            registry=registry,
            data_cutoff_date=run_result.data_cutoff_date,
        )
        normalized_peers.append(
            {
                **{key: raw_peer[key] for key in _PEER_SELECTION_FIELDS - {"fact_bindings"}},
                "fact_bindings": bindings,
                "futu_peer_session_fingerprint": futu_peer.fingerprint,
            }
        )
        peer_ids.add(peer_id)
        security_ids.add(security_id)
    if security_ids != set(futu_by_security):
        raise ValuationSynthesisError("Futu peer set differs from the frozen selection")
    if set(registries) != {item["issuer_id"] for item in normalized_peers}:
        raise ValuationSynthesisError("peer graph set differs from the frozen selection")
    normalized_peers.sort(key=lambda item: item["security_id"])
    first_request = min(
        datetime.fromisoformat(item.request_started_at.replace("Z", "+00:00"))
        for peer in futu_peer_evidence_set.peers
        for item in peer.execution.requests
    )
    if datetime.fromisoformat(frozen_at.replace("Z", "+00:00")) >= first_request:
        raise ValuationSynthesisError("peer selection did not precede every Futu read")
    forecast = to_json_value(forecast_review.reviewed_payload)
    if (
        not isinstance(forecast, dict)
        or set(forecast) != {"metric_inputs"}
        or not isinstance(forecast["metric_inputs"], Sequence)
        or isinstance(forecast["metric_inputs"], (str, bytes))
        or len(forecast["metric_inputs"]) != len(registered_metrics)
    ):
        raise ValuationSynthesisError(
            "price-blind comparable forecast does not match pre-registration"
        )
    peer_by_id = {item["peer_id"]: item for item in normalized_peers}
    futu_by_peer_id = {
        peer["peer_id"]: futu_by_security[peer["security_id"]]
        for peer in normalized_peers
    }
    normalized_metrics: list[dict[str, Any]] = []
    seen_metrics: set[str] = set()
    for raw_metric in forecast["metric_inputs"]:
        if not isinstance(raw_metric, Mapping) or set(raw_metric) != {
            "metric",
            "peer_inputs",
            "scenarios",
        }:
            raise ValuationSynthesisError("comparable forecast fields are not closed")
        metric = raw_metric["metric"]
        if metric not in registered_metrics or metric in seen_metrics:
            raise ValuationSynthesisError("comparable metric differs from pre-registration")
        observations = raw_metric["peer_inputs"]
        if not isinstance(observations, Sequence) or isinstance(observations, (str, bytes)):
            raise ValuationSynthesisError("peer comparable inputs must be a sequence")
        normalized_observations: list[dict[str, Any]] = []
        observed_ids: set[str] = set()
        for observation in observations:
            if not isinstance(observation, Mapping) or set(observation) != {
                "peer_id",
                "measure_fact_binding",
                "share_fact_binding",
                "twelve_month_measure_per_share",
            }:
                raise ValuationSynthesisError("peer forecast input fields are not closed")
            peer_id = observation["peer_id"]
            if peer_id not in peer_by_id or peer_id in observed_ids:
                raise ValuationSynthesisError("peer observation identity is invalid")
            peer = peer_by_id[peer_id]
            registry = registries[peer["issuer_id"]]
            measure_binding = _peer_fact_binding(
                observation["measure_fact_binding"],
                peer_issuer_id=peer["issuer_id"],
                registry=registry,
                data_cutoff_date=run_result.data_cutoff_date,
            )
            share_binding = _peer_fact_binding(
                observation["share_fact_binding"],
                peer_issuer_id=peer["issuer_id"],
                registry=registry,
                data_cutoff_date=run_result.data_cutoff_date,
            )
            measure_fact = registry[measure_binding["object_id"]][1]
            share_fact = registry[share_binding["object_id"]][1]
            if (
                getattr(measure_fact, "concept", None) not in _METRIC_FACT_CONCEPTS[metric]
                or getattr(measure_fact, "value_type", None) != "number"
                or getattr(measure_fact, "unit", None) != "currency_units"
                or getattr(measure_fact, "currency", None) != "USD"
                or getattr(share_fact, "concept", None)
                != "weighted_average_diluted_shares"
                or getattr(share_fact, "value_type", None) != "number"
                or getattr(share_fact, "unit", None) != "shares"
                or getattr(share_fact, "currency", None) is not None
            ):
                raise ValuationSynthesisError(
                    "peer multiple operands do not have registered SEC/IR semantics"
                )
            _require_current_comparable_period_policy(
                metric=metric,
                peer=peer,
                registry=registry,
                measure_fact=measure_fact,
                share_fact=share_fact,
                valuation_date=run_result.data_cutoff_date,
            )
            with localcontext(_VALUATION_DECIMAL_CONTEXT):
                current_measure_per_share = _positive(
                    measure_fact.value, "peer current measure"
                ) / _positive(share_fact.value, "peer current shares")
                current_multiple = _positive(
                    futu_by_peer_id[peer_id].daily_close.close_decimal,
                    "peer Futu close",
                ) / current_measure_per_share
                future_measure = _positive(
                    observation["twelve_month_measure_per_share"],
                    "peer price-blind twelve-month measure",
                )
                future_multiple = _positive(
                    futu_by_peer_id[peer_id].daily_close.close_decimal,
                    "peer Futu close",
                ) / future_measure
            normalized_observations.append(
                {
                    "peer_id": peer_id,
                    "current_measure_per_share": _decimal_text(current_measure_per_share),
                    "twelve_month_measure_per_share": _decimal_text(future_measure),
                    "current_multiple": _decimal_text(current_multiple),
                    "twelve_month_multiple": _decimal_text(future_multiple),
                    "fact_bindings": (measure_binding, share_binding),
                    "futu_peer_session_fingerprint": peer[
                        "futu_peer_session_fingerprint"
                    ],
                }
            )
            observed_ids.add(peer_id)
        if observed_ids != set(peer_by_id):
            raise ValuationSynthesisError(
                "complete-case policy forbids dropping a preselected peer"
            )
        scenarios = raw_metric["scenarios"]
        if not isinstance(scenarios, Sequence) or len(scenarios) != 3:
            raise ValuationSynthesisError("each comparable metric requires three scenarios")
        normalized_scenarios: dict[str, dict[str, str]] = {}
        for raw_scenario in scenarios:
            if not isinstance(raw_scenario, Mapping) or set(raw_scenario) != {
                "name",
                "current_target_measure_per_share",
                "twelve_month_target_measure_per_share",
                "current_net_debt_per_share",
                "twelve_month_net_debt_per_share",
            }:
                raise ValuationSynthesisError("comparable scenario fields are not closed")
            name = raw_scenario["name"]
            if name not in _SCENARIOS or name in normalized_scenarios:
                raise ValuationSynthesisError("comparable scenario names are not closed")
            normalized_scenarios[name] = {
                "name": name,
                "current_target_measure_per_share": _decimal_text(
                    _positive(
                        raw_scenario["current_target_measure_per_share"],
                        "current target measure",
                    )
                ),
                "twelve_month_target_measure_per_share": _decimal_text(
                    _positive(
                        raw_scenario["twelve_month_target_measure_per_share"],
                        "twelve-month target measure",
                    )
                ),
                "current_net_debt_per_share": _decimal_text(
                    _decimal(
                        raw_scenario["current_net_debt_per_share"],
                        "current net debt per share",
                    )
                ),
                "twelve_month_net_debt_per_share": _decimal_text(
                    _decimal(
                        raw_scenario["twelve_month_net_debt_per_share"],
                        "twelve-month net debt per share",
                    )
                ),
            }
            if (
                normalized_scenarios[name]["current_net_debt_per_share"] != "0"
                or normalized_scenarios[name]["twelve_month_net_debt_per_share"] != "0"
            ):
                raise ValuationSynthesisError(
                    "equity comparable forecasts cannot apply an EV bridge"
                )
        if set(normalized_scenarios) != set(_SCENARIOS):
            raise ValuationSynthesisError("comparable metric lacks a required scenario")
        normalized_metrics.append(
            {
                "metric": metric,
                "peer_observations": sorted(
                    normalized_observations, key=lambda item: item["peer_id"]
                ),
                "scenarios": [normalized_scenarios[name] for name in _SCENARIOS],
            }
        )
        seen_metrics.add(metric)
    if seen_metrics != set(registered_metrics):
        raise ValuationSynthesisError("not all pre-registered metrics were retained")
    normalized_metrics.sort(key=lambda item: item["metric"])
    return frozen_at, tuple(normalized_peers), tuple(normalized_metrics)


@dataclass(frozen=True, slots=True)
class ReviewedPeerSetAuthority:
    """Peer selection and price-blind forecasts frozen before exact Futu calls."""

    schema_version: str
    authority_id: str
    issuer_id: str
    target_security_id: str
    selection_frozen_at: str
    run_result: ValuationRunResult = field(repr=False)
    selection_review: NamedHumanReviewAuthority = field(repr=False)
    forecast_review: NamedHumanReviewAuthority = field(repr=False)
    peer_graphs: tuple[ContractGraph, ...] = field(repr=False)
    futu_peer_evidence_set: FutuPeerEvidenceSet = field(repr=False)
    verifier: object = field(repr=False, compare=False)
    peer_set: tuple[FrozenMap, ...]
    metric_inputs: tuple[FrozenMap, ...]
    authority_fingerprint: str

    @_valuation_decimal_scope
    def __post_init__(self) -> None:
        object.__setattr__(self, "peer_graphs", tuple(self.peer_graphs))
        frozen_at, peers, metrics = _normalize_peer_authority(
            run_result=self.run_result,
            selection_review=self.selection_review,
            forecast_review=self.forecast_review,
            peer_graphs=self.peer_graphs,
            futu_peer_evidence_set=self.futu_peer_evidence_set,
            verifier=self.verifier,
        )
        if (
            self.selection_frozen_at != frozen_at
            or to_json_value(self.peer_set) != to_json_value(peers)
            or to_json_value(self.metric_inputs) != to_json_value(metrics)
        ):
            raise ValuationSynthesisError(
                "reviewed peer-set public projection does not replay"
            )
        object.__setattr__(self, "selection_frozen_at", frozen_at)
        object.__setattr__(self, "peer_set", tuple(freeze(item) for item in peers))
        object.__setattr__(self, "metric_inputs", tuple(freeze(item) for item in metrics))
        values = self._manifest_values()
        expected_fingerprint = canonical_sha256(values)
        expected_id = (
            f"reviewed-peer-set:{self.issuer_id}:{expected_fingerprint[:24]}"
        )
        if (
            self.schema_version != "1.0.0"
            or self.authority_id != expected_id
            or self.authority_fingerprint != expected_fingerprint
        ):
            raise ValuationSynthesisError("reviewed peer-set identity is not deterministic")
        validate_extension_payload("reviewed-peer-set-authority", self.to_dict())

    def _manifest_values(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "issuer_id": self.issuer_id,
            "target_security_id": self.target_security_id,
            "selection_frozen_at": self.selection_frozen_at,
            "forecast_reviewer_id": self.forecast_review.reviewer_id,
            "forecast_reviewed_at": self.forecast_review.reviewed_at,
            "forecast_review_rationale": self.forecast_review.rationale,
            "run_input_receipt_fingerprint": self.run_result.input_receipt.fingerprint,
            "selection_review_fingerprint": self.selection_review.fingerprint,
            "forecast_review_fingerprint": self.forecast_review.fingerprint,
            "peer_graph_fingerprints": {
                next(
                    item.issuer_id
                    for graph_field in GRAPH_DOMAIN_TYPES
                    for item in getattr(graph, graph_field)
                    if type(getattr(item, "issuer_id", None)) is str
                ): _graph_fingerprint(graph)
                for graph in self.peer_graphs
            },
            "futu_peer_evidence_set_fingerprint": self.futu_peer_evidence_set.fingerprint,
            "peer_set": to_json_value(self.peer_set),
            "metric_inputs": to_json_value(self.metric_inputs),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._manifest_values(),
            "authority_id": self.authority_id,
            "authority_fingerprint": self.authority_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return self.authority_fingerprint


@retained_authority_replay_scope
@_valuation_decimal_scope
def build_reviewed_peer_set_authority(
    *,
    run_result: ValuationRunResult,
    selection_review: NamedHumanReviewAuthority,
    forecast_review: NamedHumanReviewAuthority,
    peer_graphs: Sequence[ContractGraph],
    futu_peer_evidence_set: FutuPeerEvidenceSet,
    verifier: object,
) -> ReviewedPeerSetAuthority:
    exact_graphs = tuple(peer_graphs)
    frozen_at, peers, metrics = _normalize_peer_authority(
        run_result=run_result,
        selection_review=selection_review,
        forecast_review=forecast_review,
        peer_graphs=exact_graphs,
        futu_peer_evidence_set=futu_peer_evidence_set,
        verifier=verifier,
    )
    provisional = {
        "schema_version": "1.0.0",
        "issuer_id": run_result.issuer_id,
        "target_security_id": futu_peer_evidence_set.target_security_id,
        "selection_frozen_at": frozen_at,
        "forecast_reviewer_id": forecast_review.reviewer_id,
        "forecast_reviewed_at": forecast_review.reviewed_at,
        "forecast_review_rationale": forecast_review.rationale,
        "run_input_receipt_fingerprint": run_result.input_receipt.fingerprint,
        "selection_review_fingerprint": selection_review.fingerprint,
        "forecast_review_fingerprint": forecast_review.fingerprint,
        "peer_graph_fingerprints": {
            next(
                item.issuer_id
                for graph_field in GRAPH_DOMAIN_TYPES
                for item in getattr(graph, graph_field)
                if type(getattr(item, "issuer_id", None)) is str
            ): _graph_fingerprint(graph)
            for graph in exact_graphs
        },
        "futu_peer_evidence_set_fingerprint": futu_peer_evidence_set.fingerprint,
        "peer_set": to_json_value(peers),
        "metric_inputs": to_json_value(metrics),
    }
    fingerprint = canonical_sha256(provisional)
    return ReviewedPeerSetAuthority(
        schema_version="1.0.0",
        authority_id=f"reviewed-peer-set:{run_result.issuer_id}:{fingerprint[:24]}",
        issuer_id=run_result.issuer_id,
        target_security_id=futu_peer_evidence_set.target_security_id,
        selection_frozen_at=frozen_at,
        run_result=run_result,
        selection_review=selection_review,
        forecast_review=forecast_review,
        peer_graphs=exact_graphs,
        futu_peer_evidence_set=futu_peer_evidence_set,
        verifier=verifier,
        peer_set=tuple(freeze(item) for item in peers),
        metric_inputs=tuple(freeze(item) for item in metrics),
        authority_fingerprint=fingerprint,
    )


def _peer_authority_replay(
    run_result: ValuationRunResult,
    authority: object,
) -> ReviewedPeerSetAuthority:
    if type(authority) is not ReviewedPeerSetAuthority:
        raise ValuationSynthesisError("comparables require exact reviewed peer authority")
    try:
        authority.__post_init__()
    except (OSError, TypeError, ValueError) as exc:
        raise ValuationSynthesisError("reviewed peer authority does not replay") from exc
    if authority.run_result != run_result or authority.issuer_id != run_result.issuer_id:
        raise ValuationSynthesisError("reviewed peer authority is bound to another run")
    return authority


def _comparable_input_payload(
    run_result: ValuationRunResult,
    basis: ValuationBasisReceipt,
    peer_authority: ReviewedPeerSetAuthority,
) -> dict[str, Any]:
    run_result, _archive, _request, _result = _completed_run(run_result)
    basis = _basis_replay(run_result, basis)
    peer_authority = _peer_authority_replay(run_result, peer_authority)
    evidence_ids = tuple(
        sorted(
            {
                binding["object_id"]
                for peer in peer_authority.peer_set
                for binding in peer["fact_bindings"]
            }
            | {
                binding["object_id"]
                for metric in peer_authority.metric_inputs
                for observation in metric["peer_observations"]
                for binding in observation["fact_bindings"]
            }
        )
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "issuer_id": basis.issuer_id,
        "valuation_date": basis.valuation_date,
        "basis_receipt_fingerprint": basis.fingerprint,
        "run_input_receipt_fingerprint": run_result.input_receipt.fingerprint,
        "peer_authority_fingerprint": peer_authority.fingerprint,
        "peer_graph_fingerprints": peer_authority.to_dict()[
            "peer_graph_fingerprints"
        ],
        "forecast_review_fingerprint": peer_authority.forecast_review.fingerprint,
        "futu_peer_evidence_set_fingerprint": (
            peer_authority.futu_peer_evidence_set.fingerprint
        ),
        "selection_frozen_at": peer_authority.selection_frozen_at,
        "peer_set": to_json_value(peer_authority.peer_set),
        "metric_inputs": to_json_value(peer_authority.metric_inputs),
        "reviewer_id": peer_authority.forecast_review.reviewer_id,
        "reviewed_at": peer_authority.forecast_review.reviewed_at,
        "evidence_ids": evidence_ids,
    }
    return _seal("comparable-input-receipt", basis.issuer_id, payload, "receipt_id")


def _comparable_result_payload(
    run_result: ValuationRunResult,
    basis: ValuationBasisReceipt,
    input_receipt: ComparableInputReceipt,
) -> dict[str, Any]:
    _completed_run(run_result)
    basis = _basis_replay(run_result, basis)
    if (
        type(input_receipt) is not ComparableInputReceipt
        or input_receipt._run_result != run_result
        or input_receipt._basis_authority != basis
    ):
        raise ValuationSynthesisError("comparable input authority changed")
    peer_ids = {item["peer_id"] for item in input_receipt.peer_set}
    metric_results: list[dict[str, Any]] = []
    for raw_metric in input_receipt.metric_inputs:
        metric = raw_metric["metric"]
        observations = raw_metric["peer_observations"]
        if {item["peer_id"] for item in observations} != peer_ids:
            raise ValuationSynthesisError("comparable calculation dropped a preselected peer")
        current_median = _median(
            [_positive(item["current_multiple"], "current multiple") for item in observations]
        )
        future_median = _median(
            [
                _positive(item["twelve_month_multiple"], "twelve-month multiple")
                for item in observations
            ]
        )
        scenario_values: list[dict[str, str]] = []
        for scenario in raw_metric["scenarios"]:
            current_measure = _positive(
                scenario["current_target_measure_per_share"], "current target measure"
            )
            future_measure = _positive(
                scenario["twelve_month_target_measure_per_share"],
                "twelve-month target measure",
            )
            current_debt = _decimal(
                scenario["current_net_debt_per_share"], "current net debt per share"
            )
            future_debt = _decimal(
                scenario["twelve_month_net_debt_per_share"],
                "twelve-month net debt per share",
            )
            if current_debt != 0 or future_debt != 0:
                raise ValuationSynthesisError("equity multiples cannot apply an EV bridge")
            with localcontext(_VALUATION_DECIMAL_CONTEXT):
                current_implied = current_median * current_measure
                future_implied = future_median * future_measure
            if current_implied <= 0 or future_implied <= 0:
                raise ValuationSynthesisError("comparable metric implies nonpositive value")
            scenario_values.append(
                {
                    "name": scenario["name"],
                    "current_implied_value_per_share": _decimal_text(current_implied),
                    "twelve_month_implied_value_per_share": _decimal_text(future_implied),
                }
            )
        metric_results.append(
            {
                "metric": metric,
                "valid_peer_ids": sorted(peer_ids),
                "current_peer_median_multiple": _decimal_text(current_median),
                "twelve_month_peer_median_multiple": _decimal_text(future_median),
                "scenario_values": scenario_values,
            }
        )
    metric_results.sort(key=lambda item: item["metric"])
    scenario_results: list[dict[str, Any]] = []
    for name in _SCENARIOS:
        values = [
            next(item for item in metric["scenario_values"] if item["name"] == name)
            for metric in metric_results
        ]
        current_value = _median(
            [
                _positive(item["current_implied_value_per_share"], "metric value")
                for item in values
            ]
        )
        future_value = _median(
            [
                _positive(item["twelve_month_implied_value_per_share"], "metric value")
                for item in values
            ]
        )
        scenario_results.append(
            {
                "name": name,
                "method_label": "PROJECT_EXTENSION_COMPARABLE_VALUATION",
                "current_value_per_share": _decimal_text(current_value),
                "twelve_month_value_per_share": _decimal_text(future_value),
                "metric_values": values,
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "extension_label": "PROJECT_EXTENSION_COMPARABLE_VALUATION",
        "status": "complete",
        "issuer_id": basis.issuer_id,
        "basis_receipt": basis.to_dict(),
        "input_receipt": input_receipt.to_dict(),
        "metric_results": metric_results,
        "scenarios": scenario_results,
        "valid_peer_count": len(peer_ids),
        "valid_multiple_count": len(metric_results),
        "issue_codes": (),
    }
    return _seal("comparable-result", basis.issuer_id, payload, "result_id")


@retained_authority_replay_scope
@_valuation_decimal_scope
def build_comparable_valuation(
    run_result: ValuationRunResult,
    *,
    basis_receipt: ValuationBasisReceipt,
    peer_authority: ReviewedPeerSetAuthority,
) -> ComparableValuationResult:
    input_receipt = ComparableInputReceipt(
        **_comparable_input_payload(run_result, basis_receipt, peer_authority),
        _run_result=run_result,
        _basis_authority=basis_receipt,
        _peer_authority=peer_authority,
    )
    return ComparableValuationResult(
        **_comparable_result_payload(run_result, basis_receipt, input_receipt),
        _run_result=run_result,
        _basis_authority=basis_receipt,
        _input_authority=input_receipt,
    )


def _mckinsey_extension_scenarios(
    request: Mapping[str, Any],
    result: Mapping[str, Any],
    basis: ValuationBasisReceipt,
) -> tuple[dict[str, str], ...]:
    by_name = _mckinsey_scenarios(result)
    raw_inputs = request.get("mckinsey", {}).get("scenarios", [])
    input_by_name = {
        item.get("name"): item for item in raw_inputs if isinstance(item, Mapping)
    }
    assumptions = {
        item.get("assumption_id"): item
        for item in request.get("assumption_ledger", {}).get("assumptions", [])
        if isinstance(item, Mapping)
    }
    future_shares = _positive(basis.twelve_month_shares, "twelve-month shares")
    future_assets = _nonnegative(
        basis.twelve_month_nonoperating_assets, "twelve-month assets"
    )
    future_claims = _nonnegative(
        basis.twelve_month_nonequity_claims, "twelve-month claims"
    )
    output: list[dict[str, str]] = []
    for name in _SCENARIOS:
        scenario = by_name[name]
        raw_input = input_by_name.get(name)
        assumption = (
            assumptions.get(raw_input.get("wacc_assumption_id"))
            if raw_input is not None
            else None
        )
        wacc_source = assumption.get("value") if assumption is not None else scenario.get("wacc")
        wacc = _positive(wacc_source, "McKinsey frozen WACC")
        if wacc >= 1:
            raise ValuationSynthesisError("McKinsey WACC is outside the finite domain")
        bridge = scenario.get("equity_bridge")
        dcf = scenario.get("enterprise_dcf")
        if not isinstance(bridge, Mapping) or not isinstance(dcf, Mapping):
            raise ValuationSynthesisError("McKinsey scenario output is incomplete")
        current_per_share = _positive(bridge.get("value_per_share"), "McKinsey value")
        operating = _decimal(dcf.get("operating_value"), "McKinsey operating value")
        cash_flows = dcf.get("explicit_free_cash_flows")
        if not isinstance(cash_flows, list) or not cash_flows:
            raise ValuationSynthesisError("McKinsey scenario lacks its first frozen FCF")
        first_fcf = _decimal(cash_flows[0], "first-year FCF")
        with localcontext(_VALUATION_DECIMAL_CONTEXT):
            future_operating = operating * (Decimal(1) + wacc) - first_fcf
            future_equity = future_operating + future_assets - future_claims
            future_per_share = future_equity / future_shares
        if future_per_share <= 0:
            raise ValuationSynthesisError("McKinsey +12m roll-forward is nonpositive")
        output.append(
            {
                "name": name,
                "method_label": (
                    "BOOK_CORE_MCKINSEY_ENTERPRISE_DCF_WITH_PROJECT_EXTENSION_12M_ROLL_FORWARD"
                ),
                "current_value_per_share": _decimal_text(current_per_share),
                "twelve_month_value_per_share": _decimal_text(future_per_share),
            }
        )
    return tuple(output)


def _panel_replay(
    run_result: ValuationRunResult,
    basis: ValuationBasisReceipt,
    panel: object,
    *,
    expected_type: type[ForwardReOIValuationResult] | type[ComparableValuationResult],
) -> str | None:
    if type(panel) is not expected_type:
        raise ValuationSynthesisError("composite panel type is invalid")
    try:
        panel.__post_init__()
    except (OSError, TypeError, ValueError) as exc:
        raise ValuationSynthesisError("composite panel no longer replays") from exc
    panel_name = (
        "forward_reoi"
        if expected_type is ForwardReOIValuationResult
        else "comparable"
    )
    if panel.status != "complete":
        return f"ineligible_{panel_name}_panel"
    if (
        panel._run_result != run_result
        or panel._basis_authority != basis
        or panel.issuer_id != basis.issuer_id
        or to_json_value(panel.basis_receipt) != basis.to_dict()
    ):
        return f"mismatched_{panel_name}_panel"
    return None


def _composite_payload(
    run_result: ValuationRunResult,
    basis: ValuationBasisReceipt,
    forward_reoi: ForwardReOIValuationResult | None,
    comparables: ComparableValuationResult | None,
) -> dict[str, Any]:
    run_result, archive, request, result = _completed_run(run_result)
    basis = _basis_replay(run_result, basis)
    mckinsey = result.get("panels", {}).get("mckinsey")
    if not isinstance(mckinsey, dict):
        raise ValuationSynthesisError("composite lacks the pinned McKinsey panel")
    mckinsey_fingerprint = canonical_sha256(mckinsey)
    issues: list[str] = []
    if forward_reoi is None:
        issues.append("missing_forward_reoi_panel")
    else:
        issue = _panel_replay(
            run_result,
            basis,
            forward_reoi,
            expected_type=ForwardReOIValuationResult,
        )
        if issue is not None:
            issues.append(issue)
    if comparables is None:
        issues.append("missing_comparable_panel")
    else:
        issue = _panel_replay(
            run_result,
            basis,
            comparables,
            expected_type=ComparableValuationResult,
        )
        if issue is not None:
            issues.append(issue)
    common: dict[str, Any] = {
        "schema_version": "1.0.0",
        "extension_label": "PROJECT_EXTENSION_UNWEIGHTED_THREE_PANEL_MEDIAN",
        "issuer_id": basis.issuer_id,
        "basis_receipt": basis.to_dict(),
        "core_archive_fingerprint": archive.fingerprint,
        "core_result_sha256": archive.manifest["valuation_result_sha256"],
        "run_input_receipt_fingerprint": run_result.input_receipt.fingerprint,
        "panel_fingerprints": {
            "mckinsey": mckinsey_fingerprint,
            "forward_reoi": forward_reoi.fingerprint if forward_reoi is not None else None,
            "comparables": comparables.fingerprint if comparables is not None else None,
        },
        "market_price": archive.market_reference.quote_price_decimal,
    }
    if issues:
        payload = {
            **common,
            "status": "blocked",
            "panel_scenarios": {},
            "current_intrinsic_value": None,
            "twelve_month_target": None,
            "current_relative_dispersion": None,
            "twelve_month_relative_dispersion": None,
            "margin_of_safety": None,
            "twelve_month_upside": None,
            "contested": False,
            "recommendation_eligible": False,
            "issue_codes": tuple(sorted(issues)),
        }
        return _seal("composite-valuation-result", basis.issuer_id, payload, "result_id")
    assert forward_reoi is not None and comparables is not None
    mckinsey_scenarios = _mckinsey_extension_scenarios(request, result, basis)
    forward_scenarios = tuple(to_json_value(item) for item in forward_reoi.scenarios)
    comparable_scenarios = tuple(to_json_value(item) for item in comparables.scenarios)
    if any(
        tuple(item["name"] for item in scenarios) != _SCENARIOS
        for scenarios in (mckinsey_scenarios, forward_scenarios, comparable_scenarios)
    ):
        raise ValuationSynthesisError("three valuation panels do not share one scenario basis")
    base_rows = (
        mckinsey_scenarios[1],
        forward_scenarios[1],
        comparable_scenarios[1],
    )
    current_values = [
        _positive(item["current_value_per_share"], "base current panel value")
        for item in base_rows
    ]
    future_values = [
        _positive(item["twelve_month_value_per_share"], "base +12m panel value")
        for item in base_rows
    ]
    with localcontext(_VALUATION_DECIMAL_CONTEXT):
        current_median = _median(current_values)
        future_median = _median(future_values)
        current_dispersion = (max(current_values) - min(current_values)) / abs(
            current_median
        )
        future_dispersion = (max(future_values) - min(future_values)) / abs(future_median)
        market_price = _positive(archive.market_reference.quote_price_decimal, "market price")
        margin_of_safety = (current_median - market_price) / current_median
        future_upside = (future_median - market_price) / market_price
    current_contested = current_dispersion > _DISPERSION_LIMIT
    twelve_month_contested = future_dispersion > _DISPERSION_LIMIT
    contested = current_contested or twelve_month_contested
    issue_codes = tuple(
        issue_code
        for is_contested, issue_code in (
            (
                current_contested,
                "current_panel_dispersion_exceeds_50_percent",
            ),
            (
                twelve_month_contested,
                "twelve_month_panel_dispersion_exceeds_50_percent",
            ),
        )
        if is_contested
    )
    payload = {
        **common,
        "status": "contested" if contested else "complete",
        "panel_scenarios": {
            "mckinsey": mckinsey_scenarios,
            "forward_reoi": forward_scenarios,
            "comparables": comparable_scenarios,
        },
        "current_intrinsic_value": (
            None if current_contested else _decimal_text(current_median)
        ),
        "twelve_month_target": (
            None if twelve_month_contested else _decimal_text(future_median)
        ),
        "current_relative_dispersion": _decimal_text(current_dispersion),
        "twelve_month_relative_dispersion": _decimal_text(future_dispersion),
        "market_price": _decimal_text(market_price),
        "margin_of_safety": (
            None if current_contested else _decimal_text(margin_of_safety)
        ),
        "twelve_month_upside": (
            None if twelve_month_contested else _decimal_text(future_upside)
        ),
        "contested": contested,
        "recommendation_eligible": not contested,
        "issue_codes": issue_codes,
    }
    return _seal("composite-valuation-result", basis.issuer_id, payload, "result_id")


@retained_authority_replay_scope
@_valuation_decimal_scope
def build_composite_valuation(
    run_result: ValuationRunResult,
    *,
    basis_receipt: ValuationBasisReceipt,
    forward_reoi: ForwardReOIValuationResult | None,
    comparables: ComparableValuationResult | None,
) -> CompositeValuationResult:
    return CompositeValuationResult(
        **_composite_payload(run_result, basis_receipt, forward_reoi, comparables),
        _run_result=run_result,
        _basis_authority=basis_receipt,
        _forward_authority=forward_reoi,
        _comparable_authority=comparables,
    )


@_valuation_decimal_scope
def _replay_extension_contract(contract: ExtensionContract) -> None:
    if type(contract) is ValuationBasisReceipt:
        expected = _basis_payload(contract._run_result, contract._review_authority)
    elif type(contract) is ForwardReOIInputReceipt:
        expected = _forward_input_payload(
            contract._run_result,
            contract._basis_authority,
            contract._review_authority,
        )
    elif type(contract) is ForwardReOIValuationResult:
        expected = _forward_result_payload(
            contract._run_result,
            contract._basis_authority,
            contract._input_authority,
        )
    elif type(contract) is ComparableInputReceipt:
        expected = _comparable_input_payload(
            contract._run_result,
            contract._basis_authority,
            contract._peer_authority,
        )
    elif type(contract) is ComparableValuationResult:
        expected = _comparable_result_payload(
            contract._run_result,
            contract._basis_authority,
            contract._input_authority,
        )
    elif type(contract) is CompositeValuationResult:
        expected = _composite_payload(
            contract._run_result,
            contract._basis_authority,
            contract._forward_authority,
            contract._comparable_authority,
        )
    else:
        raise ValuationSynthesisError(
            f"{type(contract).__name__} retained-authority replay is unavailable"
        )
    if contract.to_dict() != to_json_value(expected):
        raise ValuationSynthesisError(
            f"{type(contract).__name__} public projection does not replay"
        )


__all__ = (
    "ReviewedPeerSetAuthority",
    "ValuationSynthesisError",
    "build_comparable_valuation",
    "build_composite_valuation",
    "build_forward_reoi_valuation",
    "build_reviewed_peer_set_authority",
    "build_valuation_basis_receipt",
)
