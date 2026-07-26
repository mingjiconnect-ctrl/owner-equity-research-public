#!/usr/bin/env python3
"""Verify that a built wheel contains only the intended public package assets."""

from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import ZipFile

REQUIRED = {
    "owner_research/__init__.py",
    "owner_research/contracts.py",
    "owner_research/schemas/source-document.schema.json",
    "owner_research/schemas/filing-artifact.schema.json",
    "owner_research/schemas/business-model-snapshot.schema.json",
    "owner_research/schemas/management-statement.schema.json",
    "owner_research/schemas/capital-allocation-event.schema.json",
    "owner_research/research_bundle_builder.py",
    "owner_research/research_bundle_artifacts.py",
    "owner_research/schemas/research-bundle.schema.json",
    "owner_research/component-lock.json",
    "owner_research/resources/market_access/provider-registry.json",
    "owner_research/resources/market_access/calendar-registry.json",
    "owner_research/resources/market_access/calendars/XNYS-2026.json",
    "owner_research/resources/market_access/calendars/XNAS-2026.json",
    "owner_research/resources/market_access/security-identity-policy.json",
    "owner_research/resources/market_access/secret-policy.json",
    "owner_research/valuation_market_adapters.py",
    "owner_research/valuation_market_parsers.py",
    "owner_research/valuation_share_event_integration_types.py",
    "owner_research/resources/current_share/canonical-event-integration-policy.json",
}
FORBIDDEN_PREFIXES = ("tests/", "evals/", "plugins/", "docs/", ".git/")


def verify(wheel: Path) -> tuple[str, ...]:
    errors: list[str] = []
    with ZipFile(wheel) as archive:
        names = set(archive.namelist())
    missing = sorted(REQUIRED - names)
    if missing:
        errors.append(f"wheel is missing required entries: {missing}")
    forbidden = sorted(
        name for name in names if name.startswith(FORBIDDEN_PREFIXES) or name.endswith(".html")
    )
    if forbidden:
        errors.append(f"wheel contains repository-only or raw filing content: {forbidden}")
    if not any(name.endswith(".dist-info/METADATA") for name in names):
        errors.append("wheel metadata is missing")
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    errors = verify(args.wheel)
    for error in errors:
        print(error)
    if errors:
        return 1
    print(f"wheel content verification passed: {args.wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
