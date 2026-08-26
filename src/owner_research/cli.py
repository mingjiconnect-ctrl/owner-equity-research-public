from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

from .component_lock import verify_component_lock
from .schema_store import SCHEMA_NAMES, validate_payload

_SCHEMA_INPUT_MAX_BYTES = 16 * 1024 * 1024


class ValidateCLIError(ValueError):
    """A validation input is not one stable, bounded JSON file."""


def _schema_input_bytes(path: Path) -> bytes:
    absolute = Path(path).expanduser().absolute()
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ValidateCLIError("schema input is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValidateCLIError("schema input is not one regular file")
        if before.st_size > _SCHEMA_INPUT_MAX_BYTES:
            raise ValidateCLIError("schema input exceeds the 16 MiB byte limit")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, _SCHEMA_INPUT_MAX_BYTES - consumed + 1),
            )
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > _SCHEMA_INPUT_MAX_BYTES:
                raise ValidateCLIError("schema input exceeds the 16 MiB byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_uid,
                value.st_gid,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if identity(before) != identity(after) or consumed != before.st_size:
            raise ValidateCLIError("schema input changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _schema_input_payload(path: Path) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValidateCLIError("schema input repeats a JSON object member")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValidateCLIError("schema input contains a non-finite JSON number")

    try:
        return json.loads(
            _schema_input_bytes(path).decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, RecursionError) as exc:
        raise ValidateCLIError("schema input is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValidateCLIError("schema input is not valid UTF-8 JSON") from exc


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
    try:
        if args.command == "schema":
            validate_payload(args.schema, _schema_input_payload(args.input))
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
    except (OSError, TypeError, ValueError) as exc:
        print(f"owner-research-validate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ("ValidateCLIError", "build_parser", "main")
