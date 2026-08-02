from __future__ import annotations

import copy
import runpy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
CI_PATH = ROOT / ".github/workflows/ci.yml"
VERIFY = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
KERNEL_FINDINGS = VERIFY["_kernel_reader_ci_findings"]


def _workflow() -> dict:
    return yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))


def _render(workflow: dict) -> str:
    return yaml.safe_dump(workflow, sort_keys=False)


def test_kernel_reader_ci_closed_projection_is_accepted() -> None:
    assert KERNEL_FINDINGS(CI_PATH.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "mutation",
    (
        "workflow_secret",
        "disabled_revocation",
        "late_revocation",
        "job_environment",
        "continue_on_error",
        "token_escape",
        "bracket_secret_escape",
        "fake_netless_commands",
    ),
)
def test_kernel_reader_ci_adversarial_mutations_are_rejected(mutation: str) -> None:
    workflow = copy.deepcopy(_workflow())
    verify = workflow["jobs"]["verify"]
    steps = verify["steps"]
    if mutation == "workflow_secret":
        workflow["env"]["LEAKED_KERNEL_PRIVATE_KEY"] = (
            "${{ secrets.PHASE5E_KERNEL_READER_PRIVATE_KEY }}"
        )
        steps[1]["with"]["private-key"] = "${{ env.LEAKED_KERNEL_PRIVATE_KEY }}"
    elif mutation == "disabled_revocation":
        steps[4]["if"] = "false"
    elif mutation == "late_revocation":
        steps[4], steps[6] = steps[6], steps[4]
    elif mutation == "job_environment":
        verify["env"] = {"KERNEL_TOKEN": "${{ steps.kernel-reader-token.outputs.token }}"}
    elif mutation == "continue_on_error":
        steps[4]["continue-on-error"] = True
    elif mutation == "token_escape":
        steps[8]["env"] = {"LEAKED": "${{ steps.kernel-reader-token.outputs.token }}"}
    elif mutation == "bracket_secret_escape":
        steps[6]["env"] = {
            "LEAKED": "${{ secrets['PHASE5E_KERNEL_READER_PRIVATE_KEY'] }}"
        }
    elif mutation == "fake_netless_commands":
        steps[7]["run"] = (
            "sudo unshare --net -- true\n"
            "python -I scripts/verify_phase5_v1.py --mode verify\n"
        )
    else:  # pragma: no cover - parameter list is closed above
        raise AssertionError(mutation)
    findings = KERNEL_FINDINGS(_render(workflow))
    assert findings
    assert all(finding.code == "P5V1-KERNEL-READER-CI" for finding in findings)
