"""Explicit command-line entry point for one reviewed owner-valuation run."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from .fingerprints import canonical_json
from .valuation_market_execution_policies import PINNED_KERNEL_WHEEL_SHA256
from .valuation_market_provider import ReviewedFileMarketProvider
from .valuation_run import (
    ValuationRunAuthority,
    ValuationRunResult,
    run_owner_valuation,
)
from .valuation_run_context import (
    VALUATION_RUN_INPUT_FILENAME,
    load_valuation_run_input_context,
)


class ValuationCLIError(ValueError):
    """The explicit CLI lacks one required frozen authority."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="owner-research-valuation")
    commands = parser.add_subparsers(dest="command", required=True)
    complete = commands.add_parser(
        "complete",
        help="run one reviewed market reference through the pinned kernel",
    )
    complete.add_argument("--price-blind-dir", type=Path, required=True)
    complete.add_argument("--market-receipt", type=Path, required=True)
    complete.add_argument("--raw-market-evidence", type=Path, required=True)
    complete.add_argument("--kernel-wheel", type=Path, required=True)
    complete.add_argument("--output", type=Path, required=True)
    complete.add_argument(
        "--run-input",
        type=Path,
        help=("canonical valuation-run-input.json; defaults beside the price-blind directory"),
    )
    complete.add_argument(
        "--kernel-repository",
        type=Path,
        help="pinned private checkout; defaults to OWNER_VALUATION_REPO",
    )
    complete.add_argument("--timeout-seconds", type=int, default=90)
    return parser


def _regular_bytes(path: Path, label: str, maximum: int = 256 * 1024 * 1024) -> bytes:
    absolute = Path(path).expanduser().absolute()
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ValuationCLIError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValuationCLIError(f"{label} is not one bounded regular file")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValuationCLIError(f"{label} exceeds the byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or consumed != before.st_size:
            raise ValuationCLIError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _runtime_supply(kernel_wheel: Path) -> tuple[Path, Path, str]:
    wheel = Path(kernel_wheel).expanduser().absolute()
    if wheel.name != PINNED_KERNEL_WHEEL_SHA256 or wheel.parent.name != "sha256":
        raise ValuationCLIError("kernel wheel must be the pinned content-addressed object")
    if hashlib.sha256(_regular_bytes(wheel, "kernel wheel")).hexdigest() != (
        PINNED_KERNEL_WHEEL_SHA256
    ):
        raise ValuationCLIError("kernel wheel bytes do not match the pinned release")
    cas_root = wheel.parent.parent
    manifest_directory = cas_root / "manifests"
    try:
        manifests = tuple(
            sorted(
                path
                for path in manifest_directory.iterdir()
                if path.is_file() and not path.is_symlink() and path.suffix == ".json"
            )
        )
    except OSError as exc:
        raise ValuationCLIError("runtime manifest directory is unavailable") from exc
    if len(manifests) != 1:
        raise ValuationCLIError("private CAS must contain exactly one runtime manifest")
    manifest = manifests[0]
    raw = _regular_bytes(manifest, "runtime manifest", maximum=8 * 1024 * 1024)
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    if manifest.name != f"{manifest_sha256}.json":
        raise ValuationCLIError("runtime manifest is not content addressed")
    return cas_root, manifest, manifest_sha256


def _kernel_repository(value: Path | None) -> Path:
    supplied = value or (
        Path(os.environ["OWNER_VALUATION_REPO"]) if "OWNER_VALUATION_REPO" in os.environ else None
    )
    if supplied is None:
        raise ValuationCLIError("--kernel-repository or OWNER_VALUATION_REPO is required")
    repository = supplied.expanduser().absolute()
    try:
        details = repository.lstat()
    except OSError as exc:
        raise ValuationCLIError("kernel repository is unavailable") from exc
    if not stat.S_ISDIR(details.st_mode) or repository.is_symlink():
        raise ValuationCLIError("kernel repository must be a real directory")
    return repository


def _write_private_file(directory: Path, name: str, content: bytes) -> None:
    descriptor = os.open(
        directory / name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ValuationCLIError("research Bundle staging write did not complete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _summary(result: ValuationRunResult) -> dict[str, object]:
    archive = result.archive
    execution = result.execution
    return {
        "status": result.status,
        "issuer_id": result.issuer_id,
        "data_cutoff_date": result.data_cutoff_date,
        "run_input_fingerprint": result.run_input_fingerprint,
        "archive_directory": (str(archive.output_directory) if archive is not None else None),
        "archive_fingerprint": archive.fingerprint if archive is not None else None,
        "valuation_request_sha256": (
            execution.final_request_result.request_sha256
            if execution is not None and execution.status == "completed"
            else None
        ),
        "valuation_result_sha256": (
            execution.kernel_execution_receipt.result_sha256
            if execution is not None and execution.status == "completed"
            else None
        ),
        "issue_codes": result.issue_codes,
    }


def _complete(args: argparse.Namespace) -> int:
    price_blind_directory = args.price_blind_dir.expanduser().absolute()
    run_input = (
        args.run_input.expanduser().absolute()
        if args.run_input is not None
        else price_blind_directory.parent / VALUATION_RUN_INPUT_FILENAME
    )
    context = load_valuation_run_input_context(
        run_input,
        price_blind_artifact_directory=price_blind_directory,
    )
    cas_root, manifest, manifest_sha256 = _runtime_supply(args.kernel_wheel)
    repository = _kernel_repository(args.kernel_repository)
    provider = ReviewedFileMarketProvider(
        review_file=args.market_receipt.expanduser().absolute(),
        raw_evidence_file=args.raw_market_evidence.expanduser().absolute(),
    )
    authority = ValuationRunAuthority(
        price_blind_artifact_directory=price_blind_directory,
        expected_freeze=context.expected_freeze,
        expected_security=context.expected_security,
        kernel_repository=repository,
        runtime_manifest=manifest,
        runtime_manifest_file_sha256=manifest_sha256,
        cas_root=cas_root,
    )
    with tempfile.TemporaryDirectory(prefix="owner-research-bundle-") as temporary:
        bundle_directory = Path(temporary)
        os.chmod(bundle_directory, 0o700)
        for name in ("research-bundle.json", "run-manifest.json"):
            _write_private_file(bundle_directory, name, context.research_bundle_contents[name])
        directory_descriptor = os.open(bundle_directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        result = run_owner_valuation(
            graph=context.graph,
            bundle_artifact_directory=bundle_directory,
            assumption_proposals=context.assumption_proposals,
            assumption_reviews=context.assumption_reviews,
            market_provider=provider,
            kernel_wheel=args.kernel_wheel,
            output_directory=args.output,
            clock=context.clock,
            authority=authority,
            timeout_seconds=args.timeout_seconds,
        )
    print(canonical_json(_summary(result)))
    return 0 if result.status == "completed" else 2


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _complete(args)
    except (OSError, TypeError, ValueError) as exc:
        print(f"owner-research-valuation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ("ValuationCLIError", "build_parser", "main")
