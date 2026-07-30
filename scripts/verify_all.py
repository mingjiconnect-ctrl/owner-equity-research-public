#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_CREATOR = Path.home() / ".codex/skills/.system/skill-creator/scripts/quick_validate.py"
PLUGIN_VALIDATOR = Path.home() / ".codex/skills/.system/plugin-creator/scripts/validate_plugin.py"


def run(*command: str) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-manifest", type=Path)
    args = parser.parse_args()
    kernel = Path(
        os.environ.get("OWNER_VALUATION_REPO", str(ROOT.parent / "owner-valuation-kernel"))
    )
    pytest_command = [sys.executable, "-m", "pytest", "-q"]
    junit_path = None
    if args.test_manifest is not None:
        junit_path = args.test_manifest.with_suffix(".xml")
        pytest_command.append(f"--junitxml={junit_path}")
    run(*pytest_command)
    if args.test_manifest is not None and junit_path is not None:
        root = ET.parse(junit_path).getroot()
        suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
        collected = sum(int(item.attrib.get("tests", 0)) for item in suites)
        failed = sum(
            int(item.attrib.get("failures", 0)) + int(item.attrib.get("errors", 0))
            for item in suites
        )
        skipped = sum(int(item.attrib.get("skipped", 0)) for item in suites)
        args.test_manifest.write_text(
            json.dumps(
                {
                    "collected_tests": collected,
                    "passed_tests": collected - failed - skipped,
                    "skipped_tests": skipped,
                    "failed_tests": failed,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        junit_path.unlink()
    run(sys.executable, "-m", "ruff", "check", "src", "tests", "scripts")
    run(sys.executable, "-m", "compileall", "-q", "src")
    wheel = os.environ.get("OWNER_RESEARCH_WHEEL")
    if wheel:
        run(sys.executable, "scripts/verify_wheel.py", wheel)
    run(
        sys.executable,
        "scripts/verify_component_lock.py",
        "--source-repo",
        str(kernel),
        "--require-clean",
        "--require-pinned-head",
    )
    run(sys.executable, "scripts/verify_market_access_authority.py")
    plugin = ROOT / "plugins" / "owner-equity-research"
    if PLUGIN_VALIDATOR.is_file() and SKILL_CREATOR.is_file():
        run(sys.executable, str(PLUGIN_VALIDATOR), str(plugin))
        for skill in sorted((plugin / "skills").iterdir()):
            if skill.is_dir():
                run(sys.executable, str(SKILL_CREATOR), str(skill))
    else:
        print("Codex scaffold validators unavailable; repository boundary tests are authoritative")
    run(sys.executable, "scripts/verify_phase_state.py")
    run(sys.executable, "scripts/verify_phase5p_baseline.py")
    run(sys.executable, "scripts/verify_phase5e2b11_frozen_acceptance.py")
    phase_status = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    integration_command = [
        sys.executable,
        "scripts/verify_phase5e2b12a_integration_contracts.py",
    ]
    if phase_status.get("current_phase") in {
        "Phase 5E-2B.1-2B",
        "Phase 5E-2B.1-2C-gate",
        "Phase 5E-2B.1-2C",
    }:
        integration_command.append("--frozen-contract-replay")
    elif (
        ROOT / "scripts/phase5e-phase-state-performance-recovery-seal-v1.json"
    ).is_file():
        recovery_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
        ).strip()
        run(
            sys.executable,
            "scripts/verify_phase5e2b12a_acceptance_gate.py",
            "--repository",
            str(ROOT),
            "--base",
            recovery_head,
            "--verify-phase-state-performance-topology-only",
        )
        integration_command.append("--frozen-contract-replay")
    elif (
        ROOT / "scripts/phase5e-base-finalization-topology-recovery-seal-v1.json"
    ).is_file():
        parity_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
        ).strip()
        run(
            sys.executable,
            "scripts/verify_phase5e2b12a_acceptance_gate.py",
            "--repository",
            str(ROOT),
            "--base",
            parity_head,
            "--verify-base-finalization-topology-only",
        )
        integration_command.append("--frozen-contract-replay")
    elif (ROOT / "scripts/phase5e-inventory-parity-recovery-seal-v1.json").is_file():
        parity_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
        ).strip()
        run(
            sys.executable,
            "scripts/verify_phase5e2b12a_acceptance_gate.py",
            "--repository",
            str(ROOT),
            "--base",
            parity_head,
            "--verify-inventory-parity-topology-only",
        )
        integration_command.append("--frozen-contract-replay")
    elif (ROOT / "scripts/phase5e-base-audit-recovery-seal-v1.json").is_file():
        recovery_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
        ).strip()
        run(
            sys.executable,
            "scripts/verify_phase5e2b12a_acceptance_gate.py",
            "--repository",
            str(ROOT),
            "--base",
            recovery_head,
            "--verify-base-audit-recovery-topology-only",
        )
        integration_command.append("--frozen-contract-replay")
    run(*integration_command)
    print("Owner research Phase 5E-2B.1-2A integration-contract verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
