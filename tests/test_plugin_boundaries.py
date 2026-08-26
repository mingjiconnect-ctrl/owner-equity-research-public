from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
PLUGIN = ROOT / "plugins" / "owner-equity-research"


def test_plugin_contains_exactly_four_skills_and_no_personas_or_later_phase_modules() -> None:
    skills = sorted(path.name for path in (PLUGIN / "skills").iterdir() if path.is_dir())
    assert skills == [
        "owner-equity-research",
        "owner-quarterly-update",
        "owner-research-audit",
        "owner-research-publish",
    ]
    forbidden_names = {
        "publisher.py",
        "business_quality.py",
        "management.py",
        "capital_allocation.py",
        "capital_allocation_intake.py",
        "capital_allocation_compiler.py",
        "capital_allocation_evaluator.py",
        "capital_allocation_review_builder.py",
        "valuation-handoff.py",
    }
    source_files = [path for path in (ROOT / "src").rglob("*") if path.is_file()]
    assert not any(path.name.lower() in forbidden_names for path in source_files)
    assert not any("personas" in path.parts for path in source_files)


def test_only_primary_research_skill_allows_implicit_invocation() -> None:
    expected = {
        "owner-equity-research": True,
        "owner-quarterly-update": False,
        "owner-research-audit": False,
        "owner-research-publish": False,
    }
    for name, implicit in expected.items():
        config = yaml.safe_load((PLUGIN / "skills" / name / "agents" / "openai.yaml").read_text())
        assert config["policy"]["allow_implicit_invocation"] is implicit


def test_skills_admit_their_current_non_production_boundary() -> None:
    for skill_file in (PLUGIN / "skills").glob("*/SKILL.md"):
        text = skill_file.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        if skill_file.parent.name == "owner-quarterly-update":
            assert "QuarterlyReconciliation" in text
        elif skill_file.parent.name == "owner-research-publish":
            assert "closed local audit package" in text
            assert "strictly reloaded" in text
            assert "Never overwrite different content" in normalized
        assert "Do not" in text
        assert "[TODO" not in text


def test_plugin_manifest_is_development_candidate_and_has_no_runtime_connectors() -> None:
    manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    assert manifest["version"] == "1.0.0-dev.0"
    assert manifest["skills"] == "./skills/"
    assert "apps" not in manifest
    assert "mcpServers" not in manifest


def test_primary_skill_is_concise_and_routes_the_closed_comprehensive_workflows() -> None:
    skill = PLUGIN / "skills" / "owner-equity-research"
    main = (skill / "SKILL.md").read_text(encoding="utf-8")
    assert len(main.splitlines()) <= 200
    assert main.count("references/research-workflow.md") == 1
    assert main.count("references/valuation-workflow.md") == 1
    assert main.count("references/audit-workflow.md") == 1
    assert main.count("references/publication-workflow.md") == 1
    assert main.count("references/runtime-cli.md") == 1
    assert "ordinary research remains price-blind" in main.lower()
    assert "ordinary research is price-blind and makes zero futu calls" in main.lower()
    assert "use this route only for an explicit valuation intent" in main.lower()
    assert "publisher is local-only" in main.lower()
    assert "never implement trading" in main.lower()
    assert "never" in main.lower() and "account mutation" in main.lower()
    assert "it never\n  uploads" in main.lower()
    assert "Phase " not in main
    assert "PR1" not in main and "PR2" not in main and "PR3" not in main
    assert "CI" not in main
    for name in (
        "research-workflow.md",
        "valuation-workflow.md",
        "audit-workflow.md",
        "publication-workflow.md",
        "runtime-cli.md",
    ):
        assert (skill / "references" / name).is_file()
    assert not any(path.is_dir() for path in (skill / "references").iterdir())
    assert not any("persona" in path.name.lower() for path in PLUGIN.rglob("*"))


def test_primary_skill_documents_every_real_unified_cli_route_and_runtime_field() -> None:
    from owner_research.workflow_cli import build_parser

    skill = PLUGIN / "skills" / "owner-equity-research"
    reference = (skill / "references" / "runtime-cli.md").read_text(encoding="utf-8")
    parser = build_parser()
    command_action = next(action for action in parser._actions if action.dest == "command")
    routes = set(command_action.choices)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    runtime_schema = json.loads(
        (ROOT / "extension_schemas" / "owner-equity-runtime-config.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert routes == {"research", "quarterly", "valuation", "report", "publish", "audit"}
    for route in routes:
        assert f"owner-equity-research {route}" in reference
    for script_name in project["project"]["scripts"]:
        assert f"{script_name} --help" in reference
    for field in runtime_schema["required"]:
        assert f"`{field}`" in reference
    assert "This CLI does not acquire SEC/IR evidence" in reference
    assert "strictly reloads" in reference


def test_bundle_builder_boundary_allows_only_strictly_reloaded_downstream_use() -> None:
    reference = (
        PLUGIN
        / "skills"
        / "owner-equity-research"
        / "references"
        / "research-bundle-contract.md"
    ).read_text(encoding="utf-8")

    assert "These prohibitions apply to the Bundle builder itself" in reference
    assert "strict canonical reload" in reference
    assert "comprehensive orchestrator may consume the Bundle downstream" in reference
    assert "Do not expose an integration CLI" not in reference


def test_audit_skill_covers_vertical_slice_without_enabling_implicit_use() -> None:
    audit = PLUGIN / "skills" / "owner-research-audit"
    text = (audit / "SKILL.md").read_text(encoding="utf-8")
    config = yaml.safe_load((audit / "agents" / "openai.yaml").read_text())

    assert "read-only" in text
    assert "signed Futu authorities" in text
    assert "qotLogined=true" in text
    assert "trdLogined=false" in text
    assert "call_count=1" in text
    assert "valuation-run-manifest.json" in text
    assert "P0=P1=P2=P3=0" in text
    assert "P0=P1=0" not in text.replace("P0=P1=P2=P3=0", "")
    assert "McKinsey, independent forward Penman ReOI, and reviewed comparables" in text
    assert "forward Penman ReOI" in text
    assert "four isolated 5x20 lenses" in text
    assert "Chinese PDF" in text
    assert "Publisher member/byte limits" in text
    assert "no weighted target price" in text
    assert "live trading/account mutation" in text
    assert "external upload" in text
    assert config["policy"]["allow_implicit_invocation"] is False
    assert "six-file archive" in config["interface"]["default_prompt"]
    assert "quote-only Futu" in config["interface"]["default_prompt"]
    assert "local Publisher" in config["interface"]["default_prompt"]

    workflow = (
        PLUGIN
        / "skills"
        / "owner-equity-research"
        / "references"
        / "audit-workflow.md"
    ).read_text(encoding="utf-8")
    assert "P0=P1=P2=P3=0" in workflow
    assert "P0=P1=0" not in workflow.replace("P0=P1=P2=P3=0", "")


def test_development_candidate_exposes_the_three_closed_entrypoints() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["version"] == "1.0.0.dev0"
    assert project["project"]["scripts"] == {
        "owner-equity-research": "owner_research.workflow_cli:main",
        "owner-research-validate": "owner_research.cli:main",
        "owner-research-valuation": "owner_research.valuation_cli:main",
    }
    import owner_research

    expected = {
        "run_owner_valuation",
        "write_valuation_run_archive",
        "load_valuation_run_archive",
        "write_valuation_run_input_context",
        "load_valuation_run_input_context",
    }
    assert expected.issubset(owner_research.__all__)
    assert owner_research.__version__ == "1.0.0.dev0"
