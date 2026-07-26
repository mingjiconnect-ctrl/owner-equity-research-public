from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .contracts import Assumption, CalculationResult, Fact, FiscalPeriod
from .fingerprints import canonical_sha256


def expected_input_fingerprint(
    calculation: CalculationResult,
    *,
    facts: Mapping[str, Fact],
    assumptions: Mapping[str, Assumption],
    calculations: Mapping[str, CalculationResult],
    periods: Mapping[str, FiscalPeriod],
) -> str:
    payload = {
        "calculator": {
            "id": calculation.calculator_id,
            "version": calculation.calculator_version,
            "code_sha256": calculation.code_sha256,
        },
        "facts": [
            {"id": identifier, "fingerprint": facts[identifier].fingerprint}
            for identifier in sorted(calculation.input_fact_ids)
        ],
        "assumptions": [
            {"id": identifier, "fingerprint": assumptions[identifier].fingerprint}
            for identifier in sorted(calculation.input_assumption_ids)
        ],
        "calculations": [
            {
                "id": identifier,
                "output_fingerprint": calculations[identifier].output_fingerprint,
            }
            for identifier in sorted(calculation.input_calculation_ids)
        ],
        "periods": [
            {"id": identifier, "fingerprint": periods[identifier].fingerprint}
            for identifier in sorted(calculation.input_period_ids)
        ],
        "bindings": dict(calculation.input_bindings),
    }
    return canonical_sha256(payload)


def expected_output_fingerprint(calculation: CalculationResult) -> str:
    payload = calculation.to_dict()
    payload.pop("output_fingerprint")
    payload.pop("generated_at")
    return canonical_sha256(payload)


def build_calculation_result(
    payload: Mapping[str, Any],
    *,
    facts: Mapping[str, Fact],
    assumptions: Mapping[str, Assumption],
    calculations: Mapping[str, CalculationResult],
    periods: Mapping[str, FiscalPeriod] | None = None,
) -> CalculationResult:
    """Build a result through the only supported deterministic fingerprint path."""
    values = dict(payload)
    values["generator"] = "deterministic_program"
    values["input_fingerprint"] = "0" * 64
    values["output_fingerprint"] = "0" * 64
    draft = CalculationResult(**values)
    values["input_fingerprint"] = expected_input_fingerprint(
        draft,
        facts=facts,
        assumptions=assumptions,
        calculations=calculations,
        periods=periods or {},
    )
    draft = CalculationResult(**values)
    values["output_fingerprint"] = expected_output_fingerprint(draft)
    return CalculationResult(**values)
