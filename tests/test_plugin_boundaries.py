from __future__ import annotations

import json
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
        if skill_file.parent.name == "owner-quarterly-update":
            assert "QuarterlyReconciliation" in text
        elif skill_file.parent.name == "owner-research-publish":
            assert "Phase 1 shell" in text
        assert "Do not" in text
        assert "[TODO" not in text


def test_plugin_manifest_is_phase5_v1_market_slice_and_has_no_runtime_connectors() -> None:
    manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    assert manifest["version"] == "0.6.0-dev.1"
    assert manifest["skills"] == "./skills/"
    assert "apps" not in manifest
    assert "mcpServers" not in manifest


def test_primary_skill_has_phase3_management_and_business_quality_references() -> None:
    skill = PLUGIN / "skills" / "owner-equity-research"
    references = sorted(path.name for path in (skill / "references").glob("*.md"))
    assert references == [
        "accounting-quality-rules.md",
        "business-model.md",
        "business-quality-review-shadow.md",
        "capital-allocation-conservation-bridges.md",
        "capital-allocation-event-ledger.md",
        "capital-allocation-outcome-evaluator.md",
        "capital-allocation-review-shadow.md",
        "footnote-topics.md",
        "hypothesis-review.md",
        "management-commitment-compiler.md",
        "management-outcome-evaluator.md",
        "management-review-shadow.md",
        "management-source-policy.md",
        "management-statement-intake.md",
        "market-execution-policy.md",
        "mechanism-diagnostics.md",
        "research-bundle-contract.md",
        "sec-intake.md",
        "valuation-assumption-governance.md",
        "valuation-handoff-contracts.md",
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in skill.rglob("*.md")).lower()
    assert "language model" in text
    assert "cannot create a fact" in text
    assert not any("persona" in path.name.lower() for path in PLUGIN.rglob("*"))
    assert "publisher" in text


def test_audit_skill_covers_vertical_slice_without_enabling_implicit_use() -> None:
    audit = PLUGIN / "skills" / "owner-research-audit"
    text = (audit / "SKILL.md").read_text(encoding="utf-8")
    config = yaml.safe_load((audit / "agents" / "openai.yaml").read_text())

    assert "Phase 1-5D" in text
    assert "Phase 5D-5" in text
    assert "Phase 5D-6" in text
    assert "MarketReferenceSnapshot" in text
    assert "canonical price-blind input artifact" in text
    assert "ResearchBundle 1.0.0" in text
    assert "build_research_bundle" in text
    assert "write_research_bundle_artifacts" in text
    assert "load_research_bundle_artifacts" in text
    assert "ten Phase 4A schemas" in text
    assert "ten policy evaluators" in text
    assert "fixed-cutoff shadows" in text
    assert "business-quality" in text
    assert "build_business_quality_review" in text
    assert "Union Pacific" in text
    assert "machine-readable human decisions" in text
    assert "same-key disclosure deduplication" in text
    assert "Outcome evaluator" in text
    assert "conservation bridge" in text
    assert "Outcome status is code-derived" in text
    assert "build_capital_allocation_review" in text
    assert "metadata-only Shadows" in text
    assert "ValuationAssumptionCandidate" in text
    assert "Candidate/Handoff v2" in text
    assert "sole Phase 5C-1 internal compiler" in text
    assert "sole Phase 5C-2 internal quality compiler" in text
    assert "sole Phase 5C-3 internal MethodView compiler" in text
    assert "sole Phase 5C-4 internal equity-bridge compiler" in text
    assert "sole Phase 5C-5 internal successor-readiness assessor" in text
    assert "nine-role equity-bridge" in text
    assert "reviewed-file Provider" in text
    assert "canonical legal event exactly once" in text
    assert "P0=P1=0" in text
    assert "Recursive controller" not in text
    assert "G1/G2/G3/G4/G5" not in text
    assert config["policy"]["allow_implicit_invocation"] is False
    assert "accounting and method views" in config["interface"]["default_prompt"]
    assert "quote-date current common shares" in config["interface"]["default_prompt"]
    assert "reviewed market-reference Snapshot" in config["interface"]["default_prompt"]
