from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.verify_phase_state import (
    PHASE5C0_CLOSEOUT,
    PHASE5C1_CLOSEOUT,
    PHASE5C2_CLOSEOUT,
    PHASE5C3_CLOSEOUT,
    PHASE5C4_CLOSEOUT,
    PHASE5C5_CLOSEOUT,
    PHASE5D0_CLOSEOUT,
    PHASE5D1_CLOSEOUT,
    PHASE5D2_CLOSEOUT,
    PHASE5D3_CLOSEOUT,
    PHASE5D4_CLOSEOUT,
    PHASE5D5_CLOSEOUT,
    PHASE5D6_CLOSEOUT,
    PHASE5E2A1_CLOSEOUT,
    PHASE5E2A2_CLOSEOUT,
    PHASE5E2A21_CLOSEOUT,
    PHASE5E2B1_CLOSEOUT,
    PHASE5E2B11_CLOSEOUT,
    PHASE5E2B11_IMPLEMENTATION,
    PHASE5E2B_CLOSEOUT,
    _expected_phase_state,
)

ROOT = Path(__file__).parents[1]


def test_current_phase_state_is_machine_readable_and_consistent() -> None:
    state = json.loads((ROOT / "docs" / "phase-status.json").read_text(encoding="utf-8"))
    is_accepted = (ROOT / "docs/phase5e2b12a-acceptance-closeout.json").is_file()
    assert state == _expected_phase_state(accepted=is_accepted)
    assert state["prior_closeouts"] == [
        PHASE5C0_CLOSEOUT,
        PHASE5C1_CLOSEOUT,
        PHASE5C2_CLOSEOUT,
        PHASE5C3_CLOSEOUT,
        PHASE5C4_CLOSEOUT,
        PHASE5C5_CLOSEOUT,
        PHASE5D0_CLOSEOUT,
        PHASE5D1_CLOSEOUT,
        PHASE5D2_CLOSEOUT,
        PHASE5D3_CLOSEOUT,
        PHASE5D4_CLOSEOUT,
        PHASE5D5_CLOSEOUT,
        PHASE5D6_CLOSEOUT,
        PHASE5E2A1_CLOSEOUT,
        PHASE5E2A2_CLOSEOUT,
        PHASE5E2A21_CLOSEOUT,
    ]
    assert state["closeout"] == PHASE5E2B11_CLOSEOUT
    assert state["closeout"]["policy_closeout"] == PHASE5E2B1_CLOSEOUT
    assert state["closeout"]["policy_closeout"]["historical_phase5e2b_closeout"] == (
        PHASE5E2B_CLOSEOUT
    )
    assert state["closeout"]["implementation"] == PHASE5E2B11_IMPLEMENTATION
    assert state["baseline_release"] == {
        "tag": "v0.4.0-alpha.1",
        "commit": "30d6e77780175deeffc5c211749bcb0169aa1dde",
    }
    assert "conditional_authorized_next" not in state
    assert "acceptance_gate" not in state
    assert "Phase 5E-2B" not in state["prohibited"]
    if is_accepted:
        assert state["authorized_next"] == [
            "Phase 5E-2B.1-2B canonical-event roll-forward implementation"
        ]
        assert "Phase 5E-2B.1-2B" not in state["prohibited"]
    else:
        assert state["authorized_next"] == ["Phase 5E-2B.1-2A acceptance closeout"]
        assert "Phase 5E-2B.1-2B" in state["prohibited"]
    assert "Phase 5E-2B.1-2C" in state["prohibited"]
    assert "Phase 5E-2B.1-3" in state["prohibited"]
    assert "Phase 5E-2C" in state["prohibited"]
    assert "Phase 5E-2D" in state["prohibited"]
    assert "Phase 5E-3" in state["prohibited"]
    assert "Phase 5F" in state["prohibited"]
    assert state["release_tag"] is None
    accepted = _expected_phase_state(accepted=True)
    assert accepted["current_phase"] == "Phase 5E-2B.1-2A"
    assert accepted["status"] == "accepted_closed"
    assert accepted["authorized_next"] == [
        "Phase 5E-2B.1-2B canonical-event roll-forward implementation"
    ]
    assert "Phase 5E-2B.1-2C" in accepted["prohibited"]
    assert "Phase 5E-2B.1-3" in accepted["prohibited"]
    subprocess.run(
        [sys.executable, "scripts/verify_phase_state.py"],
        cwd=ROOT,
        check=True,
    )
