from __future__ import annotations

import ast
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
QUARTERLY = ROOT / "src" / "owner_research" / "quarterly.py"


def test_phase3_contains_no_phase4_to_phase7_production_modules() -> None:
    forbidden = {
        "business_quality.py",
        "management.py",
        "capital_allocation.py",
        "valuation_handoff.py",
        "scoring.py",
        "publisher.py",
        "reporting.py",
    }
    present = {path.name for path in (ROOT / "src" / "owner_research").glob("*.py")}
    assert not forbidden.intersection(present)


def test_quarterly_module_has_no_network_llm_report_or_valuation_dependency() -> None:
    tree = ast.parse(QUARTERLY.read_text(encoding="utf-8"))
    forbidden_imports = {
        "requests",
        "httpx",
        "openai",
        "reportlab",
        "weasyprint",
        "owner_valuation",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert not forbidden_imports.intersection(imports)


def test_quarterly_contracts_have_no_score_report_or_valuation_edges() -> None:
    for name in ("fiscal-period", "quarterly-reconciliation", "quarterly-update"):
        schema = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
        text = json.dumps(schema, sort_keys=True).lower()
        assert "score_id" not in text
        assert "report_artifact" not in text
        assert "valuation_result" not in text


def test_quarterly_skill_is_explicit_and_no_longer_a_phase1_shell() -> None:
    skill = ROOT / "plugins" / "owner-equity-research" / "skills" / "owner-quarterly-update"
    config = yaml.safe_load((skill / "agents" / "openai.yaml").read_text())
    text = (skill / "SKILL.md").read_text(encoding="utf-8")
    assert config["policy"]["allow_implicit_invocation"] is False
    assert "NOT_IMPLEMENTED_PHASE_2" not in text
    assert "Phase 1 shell" not in text
    assert "valuation" in text.lower()
    assert "Do not" in text


def test_no_legacy_imports_or_persona_agents() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "src" / "owner_research").glob("*.py")
    ).lower()
    assert "institutional_value_investing_equity_research" not in source
    assert "persona" not in source
