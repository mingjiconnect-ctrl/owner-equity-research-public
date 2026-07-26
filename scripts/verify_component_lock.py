#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from owner_research.component_lock import (
    verify_component_lock,
    verify_future_mapping_contract,
    verify_research_schema_lock,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("component-lock.json"))
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--require-pinned-head", action="store_true")
    args = parser.parse_args()

    root = args.lock.resolve().parent
    results = (
        verify_research_schema_lock(args.lock, root),
        verify_component_lock(
            args.lock,
            source_repo=args.source_repo,
            require_clean=args.require_clean,
            require_pinned_head=args.require_pinned_head,
        ),
        verify_future_mapping_contract(
            root / "evals" / "future-valuation-mapping.json",
            source_repo=args.source_repo,
        ),
    )
    errors = [error for result in results for error in result.errors]
    for error in errors:
        print(error)
    if errors:
        return 1
    print("component-lock verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
