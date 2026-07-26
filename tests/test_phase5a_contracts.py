from __future__ import annotations

import json
from pathlib import Path

from owner_research.schema_store import SCHEMA_NAMES
from owner_research.valuation_handoff_policies import (
    HANDOFF_STATES,
    HANDOFF_TRANSITIONS,
    MCKINSEY_CONCEPTS,
    MCKINSEY_SCENARIOS,
    PENMAN_CONCEPTS,
    method_assumption_policy,
)

ROOT = Path(__file__).parents[1]
PHASE5A_SCHEMAS = {
    "valuation-assumption-candidate",
    "valuation-assumption-review-decision",
    "market-reference-snapshot",
    "valuation-handoff",
}


def test_phase5a_adds_exactly_four_public_contracts() -> None:
    assert len(SCHEMA_NAMES) == 43
    assert PHASE5A_SCHEMAS.issubset(SCHEMA_NAMES)
    assert all((ROOT / "schemas" / f"{name}.schema.json").is_file() for name in PHASE5A_SCHEMAS)


def test_phase5a_policy_registry_is_closed() -> None:
    assert method_assumption_policy("mckinsey").concepts == MCKINSEY_CONCEPTS
    assert method_assumption_policy("mckinsey").scenarios == MCKINSEY_SCENARIOS
    assert method_assumption_policy("penman").concepts == PENMAN_CONCEPTS
    assert method_assumption_policy("penman").scenarios == frozenset()


def test_handoff_state_machine_has_only_adjacent_transitions() -> None:
    assert tuple(HANDOFF_TRANSITIONS) == HANDOFF_STATES[:-1]
    assert tuple(HANDOFF_TRANSITIONS.values()) == HANDOFF_STATES[1:]


def test_adversarial_fixture_covers_required_failure_paths() -> None:
    payload = json.loads(
        (ROOT / "tests" / "fixtures" / "phase5a" / "adversarial-cases.json").read_text()
    )
    assert payload["schema_version"] == "1.0.0"
    assert len(payload["cases"]) >= 25
    assert len(payload["cases"]) == len(set(payload["cases"]))
