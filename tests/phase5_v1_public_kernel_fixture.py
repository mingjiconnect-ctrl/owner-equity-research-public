from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from owner_research.fingerprints import canonical_sha256

ROOT = Path(__file__).parents[1]
PUBLIC_KERNEL_SCHEMA_DIRECTORY = (
    ROOT / "src" / "owner_research" / "resources" / "phase5-v1-kernel-schemas"
)
PUBLIC_KERNEL_REPOSITORY = ROOT

_SCHEMA_NAMES = (
    "fact-ledger.schema.json",
    "assumption-ledger.schema.json",
    "valuation-request.schema.json",
)
_MCKINSEY_FORECAST_PERIODS = (
    "2027-07-10",
    "2028-07-10",
    "2029-07-10",
    "2030-07-10",
    "2031-07-10",
)
_PENMAN_FORECAST_PERIODS = _MCKINSEY_FORECAST_PERIODS[:2]
_CHALLENGE_PERIODS = ("2029-07-10", "2030-07-10", "2031-07-10")
_SCENARIOS = ("black_swan", "bear", "base", "bull")
_ASSUMPTION_SOURCES = {
    "revenue": ["fact-revenue"],
    "nopat": ["fact-revenue", "fact-nopat"],
    "ending_invested_capital": ["fact-invested-capital"],
    "wacc": ["fact-risk-free", "fact-debt"],
    "terminal_growth": ["fact-revenue", "fact-market-growth"],
    "terminal_ronic": ["fact-invested-capital", "fact-nopat"],
    "terminal_margin": ["fact-revenue", "fact-nopat"],
    "terminal_roic": ["fact-invested-capital", "fact-nopat"],
    "steady_state_tolerance": ["fact-method-policy"],
    "sales": ["fact-revenue"],
    "operating_income_after_tax": ["fact-revenue", "fact-nopat"],
    "ending_noa": ["fact-noa"],
    "hurdle_rate": ["fact-risk-free", "fact-method-policy"],
    "growth_rate": ["fact-revenue", "fact-market-growth"],
}


def public_kernel_schemas() -> dict[str, dict[str, Any]]:
    """Load the repository-owned public ABI snapshot without a private checkout."""

    return {
        f"schemas/{name}": json.loads(
            (PUBLIC_KERNEL_SCHEMA_DIRECTORY / name).read_text(encoding="utf-8")
        )
        for name in _SCHEMA_NAMES
    }


def install_public_kernel_schema_oracle(monkeypatch: Any) -> None:
    """Use only the vendored public Schemas for request-compilation semantics."""

    import owner_research.valuation_final_request as final_request_module

    schemas = public_kernel_schemas()

    def verify(repository: Path) -> tuple[Path, dict[str, dict[str, Any]]]:
        if Path(repository).resolve() != PUBLIC_KERNEL_REPOSITORY.resolve():
            raise AssertionError("public semantic tests received an external kernel repository")
        return PUBLIC_KERNEL_REPOSITORY, schemas

    monkeypatch.setattr(final_request_module, "_verify_kernel", verify)


def _source() -> dict[str, Any]:
    return {
        "source_id": "source:public-fixture:2026",
        "title": "Public synthetic dual-panel contract fixture",
        "publisher": "owner-equity-research public tests",
        "published_date": "2026-06-30",
        "retrieved_at": "2026-06-30T00:00:00Z",
        "locator": "tests/phase5_v1_public_kernel_fixture.py",
        "url": "https://example.invalid/public-dual-panel-fixture",
        "local_path": None,
        "primary": True,
    }


def _fact(
    fact_id: str,
    concept: str,
    value: float,
    *,
    category: str = "accounting",
    unit: str = "USD millions",
    currency: str | None = "USD",
    stock: bool = False,
    raw: bool = True,
    parent_fact_ids: list[str] | None = None,
    derivation: str | None = None,
    equity_bridge_role: str | None = None,
) -> dict[str, Any]:
    return {
        "fact_id": fact_id,
        "concept": concept,
        "value": value,
        "unit": unit,
        "category": category,
        "source_id": "source:public-fixture:2026",
        "source_location": f"public-fixture:{fact_id}",
        "as_of_date": "2026-06-30",
        "currency": currency,
        "period_start": None if stock else "2025-07-01",
        "period_end": None if stock else "2026-06-30",
        "confidence": "high",
        "raw": raw,
        "parent_fact_ids": [] if parent_fact_ids is None else parent_fact_ids,
        "derivation": derivation,
        "equity_bridge_role": equity_bridge_role,
    }


def _facts() -> list[dict[str, Any]]:
    facts = [
        _fact("fact-assets", "total_assets", 150.0, stock=True),
        _fact("fact-liabilities", "total_liabilities", 50.0, stock=True),
        _fact("fact-equity", "common_equity", 100.0, stock=True),
        _fact("fact-beginning-equity", "beginning_common_equity", 90.0, stock=True),
        _fact("fact-ending-equity", "ending_common_equity", 100.0, stock=True),
        _fact("fact-comprehensive-income", "comprehensive_income", 15.0),
        _fact("fact-distributions", "net_distributions_to_owners", 5.0),
        _fact("fact-revenue", "revenue", 100.0, category="operating"),
        _fact("fact-nopat", "nopat", 10.0, category="operating"),
        _fact("fact-invested-capital", "invested_capital", 100.0, stock=True),
        _fact("fact-noa", "net_operating_assets", 100.0, stock=True),
        _fact(
            "fact-nfo",
            "net_financial_obligations",
            25.0,
            category="financing",
            stock=True,
        ),
        _fact(
            "fact-debt",
            "debt",
            25.0,
            category="financing",
            stock=True,
            equity_bridge_role="debt",
        ),
        _fact(
            "fact-risk-free",
            "risk_free_rate",
            0.04,
            category="market_reference",
            unit="decimal",
            currency=None,
        ),
        _fact(
            "fact-market-growth",
            "long_run_market_growth",
            0.02,
            category="market_reference",
            unit="decimal",
            currency=None,
        ),
        _fact(
            "fact-method-policy",
            "steady_state_tolerance_policy",
            0.001,
            category="evidence",
            unit="decimal",
            currency=None,
        ),
        _fact(
            "fact-current-common-shares",
            "common_shares_outstanding",
            95.0,
            category="share_count",
            unit="million shares",
            currency=None,
            stock=True,
        ),
        _fact(
            "fact-market-price-per-current-common-share",
            "market_price_per_current_common_share",
            50.125,
            category="market_price",
            unit="USD per share",
            stock=True,
        ),
        _fact(
            "fact-market-equity",
            "market_equity_value",
            4761.875,
            category="market_price",
            raw=False,
            parent_fact_ids=[
                "fact-market-price-per-current-common-share",
                "fact-current-common-shares",
            ],
            derivation="public-fixture:quote-times-current-common-shares",
        ),
    ]
    return sorted(facts, key=lambda item: item["fact_id"])


def _assumption(
    assumption_id: str,
    *,
    concept: str,
    value: float,
    unit: str,
    scope: str,
    scenario: str | None,
) -> dict[str, Any]:
    return {
        "assumption_id": assumption_id,
        "value": value,
        "unit": unit,
        "concept": concept,
        "scope": scope,
        "rationale": "Named-human-reviewed public synthetic price-blind input.",
        "source_fact_ids": _ASSUMPTION_SOURCES[concept],
        "scenario": scenario,
    }


def _method_inputs() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    assumptions: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []
    for scenario in _SCENARIOS:
        forecast: list[dict[str, Any]] = []
        for index, period_end in enumerate(_MCKINSEY_FORECAST_PERIODS, start=1):
            values = {
                "revenue": (200.0, 220.0, 242.0, 266.2, 292.82)[index - 1],
                "nopat": (20.0, 22.0, 24.2, 26.62, 29.282)[index - 1],
                "ending_invested_capital": (
                    110.0,
                    121.0,
                    133.1,
                    146.41,
                    161.051,
                )[index - 1],
            }
            identifiers = {
                concept: f"assumption:mckinsey:{scenario}:y{index}:{concept}"
                for concept in values
            }
            for concept, value in values.items():
                assumptions.append(
                    _assumption(
                        identifiers[concept],
                        concept=concept,
                        value=value,
                        unit="USD millions",
                        scope="mckinsey",
                        scenario=scenario,
                    )
                )
            forecast.append(
                {
                    "period_end": period_end,
                    "revenue_assumption_id": identifiers["revenue"],
                    "nopat_assumption_id": identifiers["nopat"],
                    "ending_invested_capital_assumption_id": identifiers[
                        "ending_invested_capital"
                    ],
                }
            )
        terminal_values = {
            "wacc": 0.12,
            "terminal_growth": 0.10,
            "terminal_ronic": 0.20,
            "terminal_margin": 0.10,
            "terminal_roic": 0.20,
            "steady_state_tolerance": 0.001,
        }
        terminal_ids = {
            concept: f"assumption:mckinsey:{scenario}:{concept}"
            for concept in terminal_values
        }
        for concept, value in terminal_values.items():
            assumptions.append(
                _assumption(
                    terminal_ids[concept],
                    concept=concept,
                    value=value,
                    unit="decimal",
                    scope="mckinsey",
                    scenario=scenario,
                )
            )
        scenarios.append(
            {
                "name": scenario,
                "wacc_assumption_id": terminal_ids["wacc"],
                "terminal_growth_assumption_id": terminal_ids["terminal_growth"],
                "terminal_ronic_assumption_id": terminal_ids["terminal_ronic"],
                "forecast": forecast,
                "steady_state": {
                    "terminal_nopat_margin_assumption_id": terminal_ids["terminal_margin"],
                    "terminal_roic_assumption_id": terminal_ids["terminal_roic"],
                    "tolerance_assumption_id": terminal_ids["steady_state_tolerance"],
                },
            }
        )

    penman_forecast: list[dict[str, Any]] = []
    for index, period_end in enumerate(_PENMAN_FORECAST_PERIODS, start=1):
        values = {
            "sales": (120.0, 132.0)[index - 1],
            "operating_income_after_tax": (18.0, 19.8)[index - 1],
            "ending_noa": (108.0, 116.0)[index - 1],
        }
        identifiers = {
            concept: f"assumption:penman:forecast:y{index}:{concept}" for concept in values
        }
        for concept, value in values.items():
            assumptions.append(
                _assumption(
                    identifiers[concept],
                    concept=concept,
                    value=value,
                    unit="USD millions",
                    scope="penman",
                    scenario=None,
                )
            )
        penman_forecast.append(
            {
                "period_end": period_end,
                "sales_assumption_id": identifiers["sales"],
                "operating_income_assumption_id": identifiers["operating_income_after_tax"],
                "ending_noa_assumption_id": identifiers["ending_noa"],
            }
        )

    primary_hurdle_id = "assumption:penman:primary-hurdle"
    assumptions.append(
        _assumption(
            primary_hurdle_id,
            concept="hurdle_rate",
            value=0.10,
            unit="decimal",
            scope="penman",
            scenario=None,
        )
    )
    hurdle_ids: list[str] = []
    for index, value in enumerate((0.08, 0.10, 0.12)):
        identifier = f"assumption:penman:hurdle:{index}"
        hurdle_ids.append(identifier)
        assumptions.append(
            _assumption(
                identifier,
                concept="hurdle_rate",
                value=value,
                unit="decimal",
                scope="penman",
                scenario=None,
            )
        )
    growth_ids: list[str] = []
    for index, value in enumerate((-0.02, 0.0, 0.04)):
        identifier = f"assumption:penman:growth:{index}"
        growth_ids.append(identifier)
        assumptions.append(
            _assumption(
                identifier,
                concept="growth_rate",
                value=value,
                unit="decimal",
                scope="penman",
                scenario=None,
            )
        )
    long_run_growth_id = "assumption:penman:long-run-growth"
    assumptions.append(
        _assumption(
            long_run_growth_id,
            concept="growth_rate",
            value=0.02,
            unit="decimal",
            scope="penman",
            scenario=None,
        )
    )
    challenge: list[dict[str, Any]] = []
    for index, period_end in enumerate(_CHALLENGE_PERIODS, start=1):
        values = {
            "sales": (145.0, 157.0, 169.0)[index - 1],
            "ending_noa": (124.0, 131.0, 138.0)[index - 1],
        }
        identifiers = {
            concept: f"assumption:penman:challenge:y{index}:{concept}" for concept in values
        }
        for concept, value in values.items():
            assumptions.append(
                _assumption(
                    identifiers[concept],
                    concept=concept,
                    value=value,
                    unit="USD millions",
                    scope="penman",
                    scenario=None,
                )
            )
        challenge.append(
            {
                "period_end": period_end,
                "sales_assumption_id": identifiers["sales"],
                "ending_noa_assumption_id": identifiers["ending_noa"],
            }
        )

    assumptions.sort(key=lambda item: item["assumption_id"])
    mckinsey = {
        "base_invested_capital_fact_id": "fact-invested-capital",
        "scenarios": scenarios,
        "equity_bridge": {
            "items": [{"item_id": "debt", "fact_id": "fact-debt"}],
            "role_assertions": _bridge_roles(),
        },
    }
    penman = {
        "current_noa_fact_id": "fact-noa",
        "net_financial_obligations_fact_id": "fact-nfo",
        "market_equity_value_fact_id": "fact-market-equity",
        "primary_hurdle_assumption_id": primary_hurdle_id,
        "hurdle_assumption_ids": hurdle_ids,
        "growth_rate_assumption_ids": growth_ids,
        "long_run_growth_assumption_id": long_run_growth_id,
        "forecast": penman_forecast,
        "market_challenge_path": challenge,
        "include_cap_diagnostic": False,
    }
    return assumptions, mckinsey, penman


def _bridge_roles() -> list[dict[str, Any]]:
    roles = (
        "nonoperating_asset",
        "debt",
        "debt_equivalent",
        "lease_liability",
        "unfunded_pension",
        "preferred_stock",
        "noncontrolling_interest",
        "option_or_dilution_claim",
        "other_senior_claim",
    )
    return [
        {
            "role": role,
            "status": "modeled" if role == "debt" else "explicitly_absent",
            "fact_id": "fact-debt" if role == "debt" else None,
            "rationale": (
                "The public synthetic debt Fact is modeled."
                if role == "debt"
                else f"The public synthetic fixture has no reviewed {role} claim."
            ),
            "source_fact_ids": (
                ["fact-debt"]
                if role == "debt"
                else ["fact-assets", "fact-liabilities", "fact-revenue"]
            ),
        }
        for role in roles
    ]


def public_kernel_example() -> dict[str, Any]:
    """Build a fictional, repo-owned public request oracle from the public ABI only."""

    facts = _facts()
    ledger = {
        "schema_version": "1.0.0",
        "entity_id": "SYNTH",
        "valuation_date": "2026-07-10",
        "reporting_currency": "USD",
        "sources": [_source()],
        "facts": facts,
    }
    assumptions, mckinsey, penman = _method_inputs()
    routing_fact_ids = {
        "required_data_complete": ["fact-revenue", "fact-nopat"],
        "stable_capital_structure": ["fact-debt", "fact-equity"],
        "operating_financing_separable": ["fact-noa", "fact-nfo"],
        "credible_noa": ["fact-noa", "fact-invested-capital"],
        "credible_near_term_earnings": ["fact-revenue", "fact-nopat"],
        "equity_bridge_complete": ["fact-debt", "fact-equity"],
    }
    return {
        "fact_ledger": ledger,
        "assumption_ledger": {
            "schema_version": "1.0.0",
            "fact_ledger_fingerprint": canonical_sha256(ledger),
            "assumptions": assumptions,
        },
        "company": {
            "classification_rationale": (
                "Public synthetic operating and financing Facts support the standard route."
            ),
            "source_fact_ids": ["fact-revenue", "fact-noa", "fact-nfo"],
        },
        "accounting_checks": {
            "balance_sheet": {
                "assets_fact_id": "fact-assets",
                "liabilities_fact_id": "fact-liabilities",
                "equity_fact_id": "fact-equity",
                "assets": 150.0,
                "liabilities": 50.0,
                "equity": 100.0,
            },
            "clean_surplus": {
                "beginning_equity_fact_id": "fact-beginning-equity",
                "comprehensive_income_fact_id": "fact-comprehensive-income",
                "net_distributions_fact_id": "fact-distributions",
                "ending_equity_fact_id": "fact-ending-equity",
                "beginning_equity": 90.0,
                "comprehensive_income": 15.0,
                "net_distributions": 5.0,
                "ending_equity": 100.0,
            },
        },
        "routing_assessments": {
            key: {
                "rationale": f"Public synthetic evidence supports {key}.",
                "source_fact_ids": fact_ids,
            }
            for key, fact_ids in routing_fact_ids.items()
        },
        "mckinsey": mckinsey,
        "penman": penman,
    }
