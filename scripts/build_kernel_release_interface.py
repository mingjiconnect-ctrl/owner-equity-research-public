#!/usr/bin/env python3
"""Build the bounded rc.2 kernel release interface used by protected audits.

The output intentionally contains no Git metadata, history, tests, documentation tree, or
credentials.  It contains only the published runtime surface, eight public schemas, release
identity manifests, and a canonical content manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

KERNEL_COMMIT = "be9b0773d5a78f5f8a33ba982494512668df85fe"
KERNEL_TAG = "v2.0.0-rc.2"
KERNEL_TAG_OBJECT = "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
RELEASE_WHEEL_SHA256 = "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5"
SCHEMA_SHA256 = {
    "assumption-ledger.schema.json": (
        "2232642332dc6444c784e21746cbd16bf8d4cd74fc483a0a345d95f98fc97a7a"
    ),
    "fact-ledger.schema.json": "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706",
    "sec-company-profile.schema.json": (
        "539b76ad7974162ba36b513c029d7d8377d352de4e150425c19c4dea620fbf06"
    ),
    "sec-company-review.schema.json": (
        "24dfa87fa94c0362569979e454cd1f536eef7c7845473567e4e88df872335205"
    ),
    "sec-evidence-pack.schema.json": (
        "3cf634214584d54d83b0d397da3139ca30815a44e99e7ecc24c3258b25a7b91a"
    ),
    "sec-scenario-policy.schema.json": (
        "74c0b0cce146891825fcf4599658f99a20fa66924cf07655895dcece00010065"
    ),
    "valuation-request.schema.json": (
        "67e991484943897585a79a8a1d3d0d52ebb36ec0ba4245cad9b17972877cca3d"
    ),
    "valuation-result.schema.json": (
        "bbfed2049ed258b767002b74ff45fb6847eb5723ffd6c1d31c53cf119625a683"
    ),
}
RELEASE_MANIFEST_SHA256 = "31687e38f24cbefa7c679e50c45191f0c31f55bcec45954ddfc58f67c42afadc"
SOURCE_MANIFEST_SHA256 = "36304f042fc8c3d090fc70477d29a8d0bd616ac68619df813a9f17b8195bf5af"
RUNTIME_ALLOWLIST = (
    "src/owner_valuation/__init__.py",
    "src/owner_valuation/assumptions.py",
    "src/owner_valuation/contracts.py",
    "src/owner_valuation/errors.py",
    "src/owner_valuation/facts.py",
    "src/owner_valuation/mckinsey.py",
    "src/owner_valuation/penman.py",
    "src/owner_valuation/pipeline.py",
    "src/owner_valuation/routing.py",
    "src/owner_valuation/validation.py",
    "src/owner_valuation/schemas/assumption-ledger.schema.json",
    "src/owner_valuation/schemas/fact-ledger.schema.json",
    "src/owner_valuation/schemas/sec-company-profile.schema.json",
    "src/owner_valuation/schemas/sec-company-review.schema.json",
    "src/owner_valuation/schemas/sec-evidence-pack.schema.json",
    "src/owner_valuation/schemas/sec-scenario-policy.schema.json",
    "src/owner_valuation/schemas/valuation-request.schema.json",
    "src/owner_valuation/schemas/valuation-result.schema.json",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *arguments],
        text=True,
    ).strip()


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)


def _copy(source: Path, destination: Path) -> None:
    if not _regular_file(source):
        raise SystemExit(f"kernel release interface source is not a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o444)


def _runtime_paths(kernel: Path) -> tuple[Path, ...]:
    paths = tuple(kernel / relative for relative in RUNTIME_ALLOWLIST)
    if any(not _regular_file(path) for path in paths):
        raise SystemExit("pinned kernel runtime allowlist is incomplete or non-regular")
    return paths


def build_interface(*, kernel: Path, output: Path) -> dict[str, Any]:
    kernel = kernel.resolve()
    output = output.resolve()
    if output.exists():
        raise SystemExit("kernel release interface output must not already exist")
    if (
        _git(kernel, "rev-parse", "HEAD") != KERNEL_COMMIT
        or _git(kernel, "rev-parse", KERNEL_TAG) != KERNEL_TAG_OBJECT
        or _git(kernel, "cat-file", "-t", KERNEL_TAG) != "tag"
        or _git(kernel, "rev-parse", f"{KERNEL_TAG}^{{}}") != KERNEL_COMMIT
        or _git(kernel, "status", "--porcelain=v1")
    ):
        raise SystemExit("pinned kernel checkout identity is not exact and clean")
    output.mkdir(mode=0o755)
    copied: dict[str, str] = {}

    for source in _runtime_paths(kernel):
        relative = source.relative_to(kernel).as_posix()
        destination = output / "kernel" / relative
        _copy(source, destination)
        copied[f"kernel/{relative}"] = _sha256(destination)

    for name, expected_sha in sorted(SCHEMA_SHA256.items()):
        source = kernel / "schemas" / name
        if _sha256(source) != expected_sha:
            raise SystemExit(f"pinned kernel schema drifted: {name}")
        destination = output / "kernel" / "schemas" / name
        _copy(source, destination)
        copied[f"kernel/schemas/{name}"] = expected_sha

    fixed_files = {
        "kernel/pyproject.toml": (kernel / "pyproject.toml", None),
        "kernel/references/release_manifest.json": (
            kernel / "references" / "release_manifest.json",
            RELEASE_MANIFEST_SHA256,
        ),
        "kernel/references/source_manifest.json": (
            kernel / "references" / "source_manifest.json",
            SOURCE_MANIFEST_SHA256,
        ),
        "kernel/plugins/owner-valuation/.codex-plugin/plugin.json": (
            kernel / "plugins" / "owner-valuation" / ".codex-plugin" / "plugin.json",
            None,
        ),
    }
    for relative, (source, expected_sha) in fixed_files.items():
        actual_sha = _sha256(source)
        if expected_sha is not None and actual_sha != expected_sha:
            raise SystemExit(f"pinned kernel manifest drifted: {relative}")
        destination = output / relative
        _copy(source, destination)
        copied[relative] = actual_sha

    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "repository": "mingjiconnect-ctrl/owner-valuation-kernel",
        "tag": KERNEL_TAG,
        "annotated_tag_object": KERNEL_TAG_OBJECT,
        "commit": KERNEL_COMMIT,
        "package_version": "2.0.0rc2",
        "plugin_version": "2.0.0-rc.2",
        "expected_release_wheel_sha256": RELEASE_WHEEL_SHA256,
        "files": dict(sorted(copied.items())),
    }
    manifest["interface_sha256"] = _canonical_sha256(manifest)
    manifest_path = output / "kernel-release-interface.json"
    manifest_path.write_text(
        json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o444)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel-repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_interface(
        kernel=args.kernel_repository,
        output=args.output,
    )
    print(manifest["interface_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
