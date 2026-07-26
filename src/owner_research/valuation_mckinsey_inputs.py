"""Internal Phase 5D-3 McKinsey four-scenario input compiler."""

from __future__ import annotations

import json
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
from .valuation_handoff_policies import (
    MCKINSEY_SCENARIOS,
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_TAG,
)

MCKINSEY_INPUT_POLICY_ID = "mckinsey-scenario-input"
MCKINSEY_INPUT_POLICY_VERSION = "1.0.0"
KERNEL_MCKINSEY_MODULE_SHA256 = (
    "350b67beb1f56403c422c2239eb0e6893a3a30bc4bf87578548600128d9cec67"
)

_SCENARIO_ORDER = ("black_swan", "bear", "base", "bull")
_FORECAST_CONCEPTS = ("revenue", "nopat", "ending_invested_capital")
_TERMINAL_CONCEPTS = (
    "wacc",
    "terminal_growth",
    "terminal_ronic",
    "terminal_margin",
    "terminal_roic",
    "steady_state_tolerance",
)
_FORECAST_SLOT = re.compile(
    r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\.forecast\."
    r"(?P<year>[0-9]{4})\.(?P<concept>revenue|nopat|ending_invested_capital)$"
)
_TERMINAL_SLOT = re.compile(
    r"^mckinsey\.(?P<scenario>black_swan|bear|base|bull)\."
    r"(?P<concept>wacc|terminal_growth|terminal_ronic|terminal_margin|terminal_roic|"
    r"steady_state_tolerance)$"
)


class McKinseyScenarioCompilationError(ValueError):
    """Raised when four price-blind McKinsey scenarios cannot be replayed."""


@dataclass(frozen=True, slots=True)
class McKinseyScenarioCompilationResult:
    """Immutable, price-blind McKinsey input fragment plus steady-state evidence."""

    issuer_id: str
    data_cutoff_date: str
    candidate_compilation_fingerprint: str
    assumption_ledger_fingerprint: str
    assumption_entries_sha256: str
    policy_id: str
    policy_version: str
    base_invested_capital_fact_id: str
    scenario_payload: FrozenMap
    steady_state_evidence: tuple[FrozenMap, ...]
    kernel_mckinsey_module_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_payload", freeze(self.scenario_payload))
        evidence = tuple(
            sorted(
                (freeze(item) for item in self.steady_state_evidence),
                key=lambda item: _SCENARIO_ORDER.index(item["name"]),
            )
        )
        object.__setattr__(self, "steady_state_evidence", evidence)
        if (self.policy_id, self.policy_version) != (
            MCKINSEY_INPUT_POLICY_ID,
            MCKINSEY_INPUT_POLICY_VERSION,
        ):
            raise ValueError("McKinsey scenario policy identity is invalid")
        scenarios = self.scenario_payload["scenarios"]
        if tuple(item["name"] for item in scenarios) != _SCENARIO_ORDER:
            raise ValueError("McKinsey scenario payload must contain the four ordered scenarios")
        if tuple(item["name"] for item in evidence) != _SCENARIO_ORDER:
            raise ValueError("McKinsey steady-state evidence must cover all scenarios")
        if self.kernel_mckinsey_module_sha256 != KERNEL_MCKINSEY_MODULE_SHA256:
            raise ValueError("pinned McKinsey module identity is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "candidate_compilation_fingerprint": self.candidate_compilation_fingerprint,
            "assumption_ledger_fingerprint": self.assumption_ledger_fingerprint,
            "assumption_entries_sha256": self.assumption_entries_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "base_invested_capital_fact_id": self.base_invested_capital_fact_id,
            "scenario_payload": to_json_value(self.scenario_payload),
            "steady_state_evidence": [
                to_json_value(item) for item in self.steady_state_evidence
            ],
            "kernel_mckinsey_module_sha256": self.kernel_mckinsey_module_sha256,
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
        raise McKinseyScenarioCompilationError(
            "pinned kernel checkout cannot be verified"
        ) from exc


def _verify_kernel(kernel_repository: Path) -> Path:
    kernel = Path(kernel_repository).expanduser().resolve()
    module = kernel / "src" / "owner_valuation" / "mckinsey.py"
    if (
        _git(kernel, "rev-parse", "HEAD") != PINNED_KERNEL_COMMIT
        or _git(kernel, "rev-parse", f"{PINNED_KERNEL_TAG}^{{}}")
        != PINNED_KERNEL_COMMIT
        or not module.is_file()
        or file_sha256(module) != KERNEL_MCKINSEY_MODULE_SHA256
    ):
        raise McKinseyScenarioCompilationError("pinned McKinsey module changed")
    return kernel


def _base_invested_capital(ledger: dict[str, Any]) -> dict[str, Any]:
    eligible = [
        item
        for item in ledger["facts"]
        if item["concept"] == "invested_capital"
        and item["period_start"] is None
        and item["period_end"] <= ledger["valuation_date"]
        and item["currency"] == ledger["reporting_currency"]
        and item["unit"] == f"{ledger['reporting_currency']} millions"
        and not item["raw"]
        and item["derivation"]
    ]
    latest_date = max((item["period_end"] for item in eligible), default=None)
    current = [item for item in eligible if item["period_end"] == latest_date]
    if len(current) != 1 or current[0]["value"] <= 0:
        raise McKinseyScenarioCompilationError(
            "one positive current invested-capital Fact is required"
        )
    return current[0]


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
        raise McKinseyScenarioCompilationError(
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
            raise McKinseyScenarioCompilationError(
                "confirmed Decision does not bind a kernel assumption"
            )
        if candidate.method_scope != "mckinsey":
            continue
        if (
            assumption["concept"] != candidate.kernel_concept
            or assumption["scope"] != "mckinsey"
            or assumption["scenario"] != candidate.scenario
        ):
            raise McKinseyScenarioCompilationError(
                "McKinsey assumption semantics do not replay the Candidate"
            )
        if candidate.assumption_slot_id in index:
            raise McKinseyScenarioCompilationError(
                "multiple active assumptions occupy one McKinsey slot"
            )
        index[candidate.assumption_slot_id] = (candidate, assumption)
    return index


def _annual_timeline(
    index: dict[str, tuple[Any, dict[str, Any]]]
) -> tuple[tuple[str, str, str], ...]:
    by_scenario: dict[str, dict[str, dict[str, tuple[Any, dict[str, Any]]]]] = {
        scenario: {} for scenario in _SCENARIO_ORDER
    }
    for slot, bound in index.items():
        match = _FORECAST_SLOT.fullmatch(slot)
        if match is None:
            continue
        by_scenario[match["scenario"]].setdefault(match["year"], {})[
            match["concept"]
        ] = bound
    year_sets = {tuple(sorted(rows)) for rows in by_scenario.values()}
    if len(year_sets) != 1:
        raise McKinseyScenarioCompilationError(
            "all four scenarios require an identical annual forecast timeline"
        )
    years = next(iter(year_sets), ())
    if len(years) < 2:
        raise McKinseyScenarioCompilationError(
            "McKinsey scenarios require at least two annual forecast periods"
        )
    timeline: list[tuple[str, str, str]] = []
    previous_end: str | None = None
    for year in years:
        dates: set[tuple[str, str]] = set()
        for scenario in _SCENARIO_ORDER:
            concepts = by_scenario[scenario][year]
            if set(concepts) != set(_FORECAST_CONCEPTS):
                raise McKinseyScenarioCompilationError(
                    "each McKinsey forecast year requires revenue, NOPAT, and ending capital"
                )
            for candidate, assumption in concepts.values():
                horizon = to_json_value(candidate.horizon)
                if (
                    horizon.get("kind") != "period"
                    or not horizon.get("start_date")
                    or not horizon.get("end_date")
                    or not horizon["end_date"].startswith(year)
                    or assumption["unit"]
                    != next(iter(concepts.values()))[1]["unit"]
                ):
                    raise McKinseyScenarioCompilationError(
                        "McKinsey forecast horizon or unit semantics are inconsistent"
                    )
                dates.add((horizon["start_date"], horizon["end_date"]))
        if len(dates) != 1:
            raise McKinseyScenarioCompilationError(
                "forecast concepts and scenarios must share exact annual periods"
            )
        start, end = next(iter(dates))
        start_date = date.fromisoformat(start)
        end_date = date.fromisoformat(end)
        if not 364 <= (end_date - start_date).days <= 365:
            raise McKinseyScenarioCompilationError(
                "McKinsey forecast periods must be annual"
            )
        if previous_end is not None and start_date != date.fromisoformat(previous_end) + timedelta(
            days=1
        ):
            raise McKinseyScenarioCompilationError(
                "McKinsey forecast periods must be contiguous and nonoverlapping"
            )
        previous_end = end
        timeline.append((year, start, end))
    return tuple(timeline)


def _kernel_preflight(
    *, kernel_repository: Path, scenarios: list[dict[str, Any]]
) -> tuple[dict[str, Any], ...]:
    kernel = _verify_kernel(kernel_repository)
    script = r"""
import dataclasses
import json
import sys
from owner_valuation.mckinsey import ForecastPeriod, SteadyStateEvidence

payload = json.load(sys.stdin)
out = []
for scenario in payload:
    periods = [ForecastPeriod(**item) for item in scenario["periods"]]
    evidence = SteadyStateEvidence.from_forecast(
        periods,
        terminal_revenue_growth=scenario["terminal_growth"],
        terminal_nopat_margin=scenario["terminal_margin"],
        terminal_roic=scenario["terminal_roic"],
        terminal_ronic=scenario["terminal_ronic"],
        tolerance=scenario["tolerance"],
    )
    evidence.assert_credible()
    out.append({"name": scenario["name"], "evidence": dataclasses.asdict(evidence)})
json.dump(out, sys.stdout, sort_keys=True)
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
            input=json.dumps(scenarios, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            check=True,
            env=environment,
        )
        return tuple(json.loads(completed.stdout))
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise McKinseyScenarioCompilationError(
            "pinned-kernel steady-state preflight rejected the scenario inputs"
        ) from exc


def _compile_from_ledger(
    *,
    kernel_repository: Path,
    candidate_result: AssumptionCandidateCompilationResult,
    ledger_result: AssumptionLedgerCompilationResult,
) -> McKinseyScenarioCompilationResult:
    index = _slot_index(
        candidate_result=candidate_result,
        ledger_result=ledger_result,
    )
    timeline = _annual_timeline(index)
    ledger = to_json_value(ledger_result.augmented_fact_ledger_payload)
    base_capital = _base_invested_capital(ledger)
    scenario_payloads: list[dict[str, Any]] = []
    preflight_payloads: list[dict[str, Any]] = []
    expected_unit = f"{ledger['reporting_currency']} millions"
    for scenario in _SCENARIO_ORDER:
        terminal: dict[str, tuple[Any, dict[str, Any]]] = {}
        for concept in _TERMINAL_CONCEPTS:
            slot = f"mckinsey.{scenario}.{concept}"
            if slot not in index or _TERMINAL_SLOT.fullmatch(slot) is None:
                raise McKinseyScenarioCompilationError(
                    f"McKinsey scenario is missing required slot: {slot}"
                )
            terminal[concept] = index[slot]
        if any(item[1]["unit"] != "decimal" for item in terminal.values()):
            raise McKinseyScenarioCompilationError(
                "McKinsey terminal assumptions must use decimal units"
            )
        values = {key: float(item[1]["value"]) for key, item in terminal.items()}
        if (
            not 0 < values["wacc"] < 1
            or not -1 < values["terminal_growth"] < values["wacc"]
            or values["terminal_ronic"] <= 0
            or values["terminal_growth"] / values["terminal_ronic"] > 1
            or values["terminal_margin"] <= 0
            or values["terminal_roic"] <= 0
            or not 0 < values["steady_state_tolerance"] <= 0.05
        ):
            raise McKinseyScenarioCompilationError(
                "McKinsey terminal economics fail deterministic boundary checks"
            )
        forecast: list[dict[str, Any]] = []
        periods: list[dict[str, Any]] = []
        invested_capital_start = float(base_capital["value"])
        for year, _start, end in timeline:
            bound = {
                concept: index[f"mckinsey.{scenario}.forecast.{year}.{concept}"]
                for concept in _FORECAST_CONCEPTS
            }
            if any(item[1]["unit"] != expected_unit for item in bound.values()):
                raise McKinseyScenarioCompilationError(
                    "McKinsey forecast values must use the reporting currency in millions"
                )
            revenue = float(bound["revenue"][1]["value"])
            nopat = float(bound["nopat"][1]["value"])
            capital_end = float(bound["ending_invested_capital"][1]["value"])
            forecast.append(
                {
                    "period_end": end,
                    "revenue_assumption_id": bound["revenue"][1]["assumption_id"],
                    "nopat_assumption_id": bound["nopat"][1]["assumption_id"],
                    "ending_invested_capital_assumption_id": bound[
                        "ending_invested_capital"
                    ][1]["assumption_id"],
                }
            )
            periods.append(
                {
                    "label": year,
                    "nopat": nopat,
                    "invested_capital_start": invested_capital_start,
                    "invested_capital_end": capital_end,
                    "revenue": revenue,
                }
            )
            invested_capital_start = capital_end
        scenario_payloads.append(
            {
                "name": scenario,
                "wacc_assumption_id": terminal["wacc"][1]["assumption_id"],
                "terminal_growth_assumption_id": terminal["terminal_growth"][1][
                    "assumption_id"
                ],
                "terminal_ronic_assumption_id": terminal["terminal_ronic"][1][
                    "assumption_id"
                ],
                "forecast": forecast,
                "steady_state": {
                    "terminal_nopat_margin_assumption_id": terminal[
                        "terminal_margin"
                    ][1]["assumption_id"],
                    "terminal_roic_assumption_id": terminal["terminal_roic"][1][
                        "assumption_id"
                    ],
                    "tolerance_assumption_id": terminal["steady_state_tolerance"][1][
                        "assumption_id"
                    ],
                },
            }
        )
        preflight_payloads.append(
            {
                "name": scenario,
                "periods": periods,
                "terminal_growth": values["terminal_growth"],
                "terminal_margin": values["terminal_margin"],
                "terminal_roic": values["terminal_roic"],
                "terminal_ronic": values["terminal_ronic"],
                "tolerance": values["steady_state_tolerance"],
            }
        )
    evidence = _kernel_preflight(
        kernel_repository=kernel_repository,
        scenarios=preflight_payloads,
    )
    return McKinseyScenarioCompilationResult(
        issuer_id=ledger_result.issuer_id,
        data_cutoff_date=ledger_result.data_cutoff_date,
        candidate_compilation_fingerprint=candidate_result.fingerprint,
        assumption_ledger_fingerprint=ledger_result.fingerprint,
        assumption_entries_sha256=ledger_result.assumption_entries_sha256,
        policy_id=MCKINSEY_INPUT_POLICY_ID,
        policy_version=MCKINSEY_INPUT_POLICY_VERSION,
        base_invested_capital_fact_id=base_capital["fact_id"],
        scenario_payload={"scenarios": scenario_payloads},
        steady_state_evidence=tuple(evidence),
        kernel_mckinsey_module_sha256=KERNEL_MCKINSEY_MODULE_SHA256,
    )


def compile_mckinsey_scenario_inputs(
    *,
    bundle_artifact_directory: Path,
    graph: ContractGraph,
    kernel_repository: Path,
    candidate_result: AssumptionCandidateCompilationResult,
    review_requests: tuple[AssumptionReviewRequest, ...],
    supplemental_reference_closure: PriceBlindReferenceClosure | None = None,
    prior_decisions: tuple[ValuationAssumptionReviewDecision, ...] = (),
) -> McKinseyScenarioCompilationResult:
    """Replay Phase 5D-2, compile four scenario references, and preflight steady state."""

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


if set(_SCENARIO_ORDER) != MCKINSEY_SCENARIOS:
    raise RuntimeError("McKinsey scenario order and closed registry diverged")
