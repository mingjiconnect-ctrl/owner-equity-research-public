"""Internal Phase 5D-4 price-blind Penman input-reference compiler."""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .component_lock import file_sha256
from .contracts import ValuationAssumptionReviewDecision
from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .validation import ContractGraph
from .valuation_assumption_ledger import compile_reviewed_assumption_ledger
from .valuation_assumption_types import (
    AssumptionCandidateCompilationResult,
    AssumptionLedgerCompilationResult,
    AssumptionReviewRequest,
    PriceBlindReferenceClosure,
)
from .valuation_handoff_policies import PINNED_KERNEL_COMMIT, PINNED_KERNEL_TAG

PENMAN_INPUT_POLICY_ID = "penman-price-blind-input"
PENMAN_INPUT_POLICY_VERSION = "1.0.0"
KERNEL_PENMAN_MODULE_SHA256 = (
    "a540ea5f09dfb6008a09d4544f24737ca7674f11d15c48cb8d7c1e56ed4ef885"
)

_FORECAST_CONCEPTS = ("sales", "operating_income_after_tax", "ending_noa")
_CHALLENGE_CONCEPTS = ("sales", "ending_noa")
_FORECAST_SLOT = re.compile(
    r"^penman\.forecast\.(?P<year>[0-9]{4})\."
    r"(?P<concept>sales|operating_income_after_tax|ending_noa)$"
)
_CHALLENGE_SLOT = re.compile(
    r"^penman\.challenge\.(?P<year>[0-9]{4})\.(?P<concept>sales|ending_noa)$"
)
_HURDLE_GRID_SLOT = re.compile(r"^penman\.hurdle_grid\.(?P<index>[0-9]{2})$")
_GROWTH_GRID_SLOT = re.compile(r"^penman\.growth_grid\.(?P<index>[0-9]{2})$")


class PenmanInputCompilationError(ValueError):
    """Raised when the governed nonmarket Penman fragment cannot be replayed."""


@dataclass(frozen=True, slots=True)
class PenmanInputCompilationResult:
    """Immutable Penman input fragment that deliberately omits market equity value."""

    issuer_id: str
    data_cutoff_date: str
    candidate_compilation_fingerprint: str
    assumption_ledger_fingerprint: str
    assumption_entries_sha256: str
    policy_id: str
    policy_version: str
    current_noa_fact_id: str
    net_financial_obligations_fact_id: str
    penman_payload: FrozenMap
    forecast_preflight: tuple[FrozenMap, ...]
    kernel_penman_module_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "penman_payload", freeze(self.penman_payload))
        object.__setattr__(
            self,
            "forecast_preflight",
            tuple(freeze(item) for item in self.forecast_preflight),
        )
        if (self.policy_id, self.policy_version) != (
            PENMAN_INPUT_POLICY_ID,
            PENMAN_INPUT_POLICY_VERSION,
        ):
            raise ValueError("Penman input policy identity is invalid")
        if self.kernel_penman_module_sha256 != KERNEL_PENMAN_MODULE_SHA256:
            raise ValueError("pinned Penman module identity is invalid")
        forbidden = {
            "market_equity_value_fact_id",
            "market_price",
            "market_equity_value",
            "reverse_price",
            "implied_growth",
        }
        if forbidden & set(self.penman_payload):
            raise ValueError("price-blind Penman payload contains market or result fields")
        if self.penman_payload["include_cap_diagnostic"] is not False:
            raise ValueError("CAP diagnostic cannot be enabled before market authorization")

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "candidate_compilation_fingerprint": self.candidate_compilation_fingerprint,
            "assumption_ledger_fingerprint": self.assumption_ledger_fingerprint,
            "assumption_entries_sha256": self.assumption_entries_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "current_noa_fact_id": self.current_noa_fact_id,
            "net_financial_obligations_fact_id": self.net_financial_obligations_fact_id,
            "penman_payload": to_json_value(self.penman_payload),
            "forecast_preflight": [
                to_json_value(item) for item in self.forecast_preflight
            ],
            "kernel_penman_module_sha256": self.kernel_penman_module_sha256,
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _git(repository: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repository), *args],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise PenmanInputCompilationError(
            "pinned kernel checkout cannot be verified"
        ) from exc


def _verify_kernel(kernel_repository: Path) -> Path:
    kernel = Path(kernel_repository).expanduser().resolve()
    module = kernel / "src" / "owner_valuation" / "penman.py"
    if (
        _git(kernel, "rev-parse", "HEAD") != PINNED_KERNEL_COMMIT
        or _git(kernel, "rev-parse", f"{PINNED_KERNEL_TAG}^{{}}")
        != PINNED_KERNEL_COMMIT
        or not module.is_file()
        or file_sha256(module) != KERNEL_PENMAN_MODULE_SHA256
    ):
        raise PenmanInputCompilationError("pinned Penman module changed")
    return kernel


def _current_accounting_facts(ledger: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_unit = f"{ledger['reporting_currency']} millions"

    def eligible(concept: str) -> list[dict[str, Any]]:
        return [
            item
            for item in ledger["facts"]
            if item["concept"] == concept
            and item["period_start"] is None
            and item["period_end"] <= ledger["valuation_date"]
            and item["currency"] == ledger["reporting_currency"]
            and item["unit"] == expected_unit
            and not item["raw"]
            and item["derivation"]
        ]

    current: dict[str, dict[str, Any]] = {}
    for concept in ("net_operating_assets", "net_financial_obligations"):
        facts = eligible(concept)
        latest = max((item["period_end"] for item in facts), default=None)
        selected = [item for item in facts if item["period_end"] == latest]
        if len(selected) != 1:
            raise PenmanInputCompilationError(
                f"one current derived {concept} Fact is required"
            )
        current[concept] = selected[0]
    noa = current["net_operating_assets"]
    nfo = current["net_financial_obligations"]
    if noa["period_end"] != nfo["period_end"]:
        raise PenmanInputCompilationError("current NOA and NFO must share one measurement date")
    if not math.isfinite(float(noa["value"])) or float(noa["value"]) <= 0:
        raise PenmanInputCompilationError("current NOA must be finite and positive")
    if not math.isfinite(float(nfo["value"])):
        raise PenmanInputCompilationError("current NFO must be finite")
    return noa, nfo


def _active_confirmed_decisions(
    ledger_result: AssumptionLedgerCompilationResult,
) -> tuple[Any, ...]:
    superseded = {
        item.supersedes_decision_id
        for item in ledger_result.decisions
        if item.supersedes_decision_id is not None
    }
    return tuple(
        item
        for item in ledger_result.decisions
        if item.decision == "confirmed" and item.decision_id not in superseded
    )


def _slot_index(
    *,
    candidate_result: AssumptionCandidateCompilationResult,
    ledger_result: AssumptionLedgerCompilationResult,
) -> dict[str, tuple[Any, dict[str, Any]]]:
    if (
        ledger_result.candidate_compilation_fingerprint != candidate_result.fingerprint
        or ledger_result.issuer_id != candidate_result.issuer_id
        or ledger_result.data_cutoff_date != candidate_result.data_cutoff_date
    ):
        raise PenmanInputCompilationError(
            "AssumptionLedger does not replay the Candidate compilation"
        )
    candidates = {item.candidate_id: item for item in candidate_result.candidates}
    assumptions = {
        item["assumption_id"]: item
        for item in to_json_value(ledger_result.assumption_ledger_payload)["assumptions"]
    }
    index: dict[str, tuple[Any, dict[str, Any]]] = {}
    for decision in _active_confirmed_decisions(ledger_result):
        candidate = candidates.get(decision.candidate_id)
        assumption = assumptions.get(decision.reserved_kernel_assumption_id or "")
        if candidate is None or assumption is None:
            raise PenmanInputCompilationError(
                "confirmed Decision does not bind a kernel assumption"
            )
        if candidate.method_scope != "penman":
            continue
        if (
            candidate.scenario is not None
            or assumption["scenario"] is not None
            or assumption["concept"] != candidate.kernel_concept
            or assumption["scope"] != "penman"
        ):
            raise PenmanInputCompilationError(
                "Penman assumption semantics do not replay the Candidate"
            )
        if candidate.assumption_slot_id in index:
            raise PenmanInputCompilationError(
                "multiple active assumptions occupy one Penman slot"
            )
        index[candidate.assumption_slot_id] = (candidate, assumption)
    return index


def _annual_rows(
    *,
    index: dict[str, tuple[Any, dict[str, Any]]],
    pattern: re.Pattern[str],
    concepts: tuple[str, ...],
    prefix: str,
    expected_unit: str,
    after_date: str,
    minimum_periods: int,
) -> tuple[tuple[str, str, str, dict[str, tuple[Any, dict[str, Any]]]], ...]:
    by_year: dict[str, dict[str, tuple[Any, dict[str, Any]]]] = {}
    for slot, bound in index.items():
        match = pattern.fullmatch(slot)
        if match is not None:
            by_year.setdefault(match["year"], {})[match["concept"]] = bound
    years = tuple(sorted(by_year))
    if len(years) < minimum_periods:
        raise PenmanInputCompilationError(
            f"Penman {prefix} requires at least {minimum_periods} annual period(s)"
        )
    rows = []
    previous_end = after_date
    for year in years:
        bound = by_year[year]
        if set(bound) != set(concepts):
            raise PenmanInputCompilationError(
                f"each Penman {prefix} year requires {', '.join(concepts)}"
            )
        dates: set[tuple[str, str]] = set()
        for candidate, assumption in bound.values():
            horizon = to_json_value(candidate.horizon)
            if (
                horizon.get("kind") != "period"
                or not horizon.get("start_date")
                or not horizon.get("end_date")
                or not horizon["end_date"].startswith(year)
                or assumption["unit"] != expected_unit
                or not math.isfinite(float(assumption["value"]))
            ):
                raise PenmanInputCompilationError(
                    f"Penman {prefix} horizon, unit, or value is invalid"
                )
            dates.add((horizon["start_date"], horizon["end_date"]))
        if len(dates) != 1:
            raise PenmanInputCompilationError(
                f"Penman {prefix} concepts must share an exact annual period"
            )
        start, end = next(iter(dates))
        start_date = date.fromisoformat(start)
        end_date = date.fromisoformat(end)
        if not 364 <= (end_date - start_date).days <= 365:
            raise PenmanInputCompilationError(f"Penman {prefix} periods must be annual")
        if start_date != date.fromisoformat(previous_end) + timedelta(days=1):
            raise PenmanInputCompilationError(
                f"Penman {prefix} periods must be future, contiguous, and nonoverlapping"
            )
        if float(bound["sales"][1]["value"]) <= 0 or float(
            bound["ending_noa"][1]["value"]
        ) <= 0:
            raise PenmanInputCompilationError(
                f"Penman {prefix} sales and ending NOA must be positive"
            )
        rows.append((year, start, end, bound))
        previous_end = end
    return tuple(rows)


def _rate(
    index: dict[str, tuple[Any, dict[str, Any]]],
    slot: str,
    *,
    concept: str,
    horizon_kind: str,
) -> tuple[Any, dict[str, Any]]:
    if slot not in index:
        raise PenmanInputCompilationError(f"Penman input is missing required slot: {slot}")
    candidate, assumption = index[slot]
    horizon = to_json_value(candidate.horizon)
    if (
        candidate.kernel_concept != concept
        or assumption["concept"] != concept
        or assumption["unit"] != "decimal"
        or horizon.get("kind") != horizon_kind
        or not math.isfinite(float(assumption["value"]))
    ):
        raise PenmanInputCompilationError(f"Penman rate slot is semantically invalid: {slot}")
    return candidate, assumption


def _grid(
    *,
    index: dict[str, tuple[Any, dict[str, Any]]],
    pattern: re.Pattern[str],
    concept: str,
    horizon_kind: str,
    label: str,
) -> tuple[tuple[Any, dict[str, Any]], ...]:
    entries = sorted(
        (
            (int(match["index"]), bound)
            for slot, bound in index.items()
            if (match := pattern.fullmatch(slot)) is not None
        ),
        key=lambda item: item[0],
    )
    if len(entries) < 3 or [item[0] for item in entries] != list(range(len(entries))):
        raise PenmanInputCompilationError(
            f"Penman {label} requires at least three contiguous indexed entries"
        )
    bound_entries = tuple(item[1] for item in entries)
    for candidate, _assumption in bound_entries:
        _rate(
            index,
            candidate.assumption_slot_id,
            concept=concept,
            horizon_kind=horizon_kind,
        )
    values = [float(item[1]["value"]) for item in bound_entries]
    if len(set(values)) != len(values) or values != sorted(values):
        raise PenmanInputCompilationError(
            f"Penman {label} values must be unique and strictly increasing"
        )
    return bound_entries


def _kernel_preflight(
    *,
    kernel_repository: Path,
    periods: list[dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    kernel = _verify_kernel(kernel_repository)
    script = r"""
import json
import sys
from owner_valuation.penman import PenmanForecastPeriod

payload = json.load(sys.stdin)
periods = [PenmanForecastPeriod(**item) for item in payload]
json.dump(
    [{"label": item.label, "shape_valid": True} for item in periods],
    sys.stdout,
    sort_keys=True,
)
"""
    environment = os.environ.copy()
    kernel_src = str(kernel / "src")
    environment["PYTHONPATH"] = kernel_src + (
        os.pathsep + environment["PYTHONPATH"]
        if environment.get("PYTHONPATH")
        else ""
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(periods, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            check=True,
            env=environment,
        )
        return tuple(json.loads(completed.stdout))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise PenmanInputCompilationError(
            "pinned-kernel Penman forecast-shape preflight rejected the inputs"
        ) from exc


def _compile_from_ledger(
    *,
    kernel_repository: Path,
    candidate_result: AssumptionCandidateCompilationResult,
    ledger_result: AssumptionLedgerCompilationResult,
) -> PenmanInputCompilationResult:
    index = _slot_index(
        candidate_result=candidate_result,
        ledger_result=ledger_result,
    )
    ledger = to_json_value(ledger_result.augmented_fact_ledger_payload)
    current_noa, current_nfo = _current_accounting_facts(ledger)
    expected_unit = f"{ledger['reporting_currency']} millions"
    forecast_rows = _annual_rows(
        index=index,
        pattern=_FORECAST_SLOT,
        concepts=_FORECAST_CONCEPTS,
        prefix="forecast",
        expected_unit=expected_unit,
        after_date=ledger["valuation_date"],
        minimum_periods=2,
    )
    challenge_rows = _annual_rows(
        index=index,
        pattern=_CHALLENGE_SLOT,
        concepts=_CHALLENGE_CONCEPTS,
        prefix="challenge path",
        expected_unit=expected_unit,
        after_date=forecast_rows[-1][2],
        minimum_periods=1,
    )
    _, primary = _rate(
        index,
        "penman.primary_hurdle",
        concept="hurdle_rate",
        horizon_kind="point_in_time",
    )
    primary_value = float(primary["value"])
    if not 0 < primary_value < 1:
        raise PenmanInputCompilationError("Penman primary hurdle must be between zero and one")
    hurdle_grid = _grid(
        index=index,
        pattern=_HURDLE_GRID_SLOT,
        concept="hurdle_rate",
        horizon_kind="point_in_time",
        label="hurdle grid",
    )
    hurdle_values = [float(item[1]["value"]) for item in hurdle_grid]
    if any(not 0 < value < 1 for value in hurdle_values) or not (
        hurdle_values[0] <= primary_value <= hurdle_values[-1]
    ):
        raise PenmanInputCompilationError(
            "Penman hurdle grid must contain valid rates and bracket the primary hurdle"
        )
    growth_grid = _grid(
        index=index,
        pattern=_GROWTH_GRID_SLOT,
        concept="growth_rate",
        horizon_kind="terminal",
        label="growth grid",
    )
    growth_values = [float(item[1]["value"]) for item in growth_grid]
    if any(not -1 < value < primary_value for value in growth_values):
        raise PenmanInputCompilationError(
            "Penman growth grid must stay inside the finite primary-hurdle domain"
        )
    _, long_run_growth = _rate(
        index,
        "penman.long_run_growth",
        concept="growth_rate",
        horizon_kind="terminal",
    )
    long_run_value = float(long_run_growth["value"])
    if not -1 < long_run_value < primary_value:
        raise PenmanInputCompilationError(
            "Penman long-run growth must stay below the primary hurdle"
        )

    forecast_payload = []
    preflight_periods = []
    noa_start = float(current_noa["value"])
    for year, _start, end, bound in forecast_rows:
        forecast_payload.append(
            {
                "period_end": end,
                "sales_assumption_id": bound["sales"][1]["assumption_id"],
                "operating_income_assumption_id": bound[
                    "operating_income_after_tax"
                ][1]["assumption_id"],
                "ending_noa_assumption_id": bound["ending_noa"][1]["assumption_id"],
            }
        )
        noa_end = float(bound["ending_noa"][1]["value"])
        preflight_periods.append(
            {
                "label": year,
                "operating_income_after_tax": float(
                    bound["operating_income_after_tax"][1]["value"]
                ),
                "noa_start": noa_start,
                "noa_end": noa_end,
            }
        )
        noa_start = noa_end
    challenge_payload = [
        {
            "period_end": end,
            "sales_assumption_id": bound["sales"][1]["assumption_id"],
            "ending_noa_assumption_id": bound["ending_noa"][1]["assumption_id"],
        }
        for _year, _start, end, bound in challenge_rows
    ]
    preflight = _kernel_preflight(
        kernel_repository=kernel_repository,
        periods=preflight_periods,
    )
    payload = {
        "current_noa_fact_id": current_noa["fact_id"],
        "net_financial_obligations_fact_id": current_nfo["fact_id"],
        "primary_hurdle_assumption_id": primary["assumption_id"],
        "hurdle_assumption_ids": [item[1]["assumption_id"] for item in hurdle_grid],
        "growth_rate_assumption_ids": [
            item[1]["assumption_id"] for item in growth_grid
        ],
        "long_run_growth_assumption_id": long_run_growth["assumption_id"],
        "forecast": forecast_payload,
        "market_challenge_path": challenge_payload,
        "include_cap_diagnostic": False,
    }
    return PenmanInputCompilationResult(
        issuer_id=ledger_result.issuer_id,
        data_cutoff_date=ledger_result.data_cutoff_date,
        candidate_compilation_fingerprint=candidate_result.fingerprint,
        assumption_ledger_fingerprint=ledger_result.fingerprint,
        assumption_entries_sha256=ledger_result.assumption_entries_sha256,
        policy_id=PENMAN_INPUT_POLICY_ID,
        policy_version=PENMAN_INPUT_POLICY_VERSION,
        current_noa_fact_id=current_noa["fact_id"],
        net_financial_obligations_fact_id=current_nfo["fact_id"],
        penman_payload=payload,
        forecast_preflight=preflight,
        kernel_penman_module_sha256=KERNEL_PENMAN_MODULE_SHA256,
    )


def compile_penman_price_blind_inputs(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
    candidate_result: AssumptionCandidateCompilationResult,
    review_requests: tuple[AssumptionReviewRequest, ...],
    supplemental_reference_closure: PriceBlindReferenceClosure | None = None,
    prior_decisions: tuple[ValuationAssumptionReviewDecision, ...] = (),
) -> PenmanInputCompilationResult:
    """Replay Phase 5D-2 and compile only the nonmarket Penman input fragment."""

    ledger_result = compile_reviewed_assumption_ledger(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=kernel_repository,
        candidate_result=candidate_result,
        review_requests=review_requests,
        supplemental_reference_closure=supplemental_reference_closure,
        prior_decisions=prior_decisions,
    )
    return _compile_from_ledger(
        kernel_repository=Path(kernel_repository),
        candidate_result=candidate_result,
        ledger_result=ledger_result,
    )
