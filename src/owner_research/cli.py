from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .component_lock import verify_component_lock
from .schema_store import SCHEMA_NAMES, validate_payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="owner-research-validate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("schema", help="validate one public contract JSON file")
    validate.add_argument("schema", choices=SCHEMA_NAMES)
    validate.add_argument("input", type=Path)
    component = subparsers.add_parser("component-lock", help="verify pinned valuation schemas")
    component.add_argument("--lock", type=Path, default=Path("component-lock.json"))
    component.add_argument("--source-repo", type=Path, required=True)
    component.add_argument("--require-clean", action="store_true")
    component.add_argument("--require-pinned-head", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "schema":
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        validate_payload(args.schema, payload)
        return 0
    result = verify_component_lock(
        args.lock,
        source_repo=args.source_repo,
        require_clean=args.require_clean,
        require_pinned_head=args.require_pinned_head,
    )
    if result.ok:
        return 0
    for error in result.errors:
        print(error)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
