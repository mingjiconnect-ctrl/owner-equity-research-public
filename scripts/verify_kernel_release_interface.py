#!/usr/bin/env python3
"""Independently verify the bounded rc.2 kernel release interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from build_kernel_release_interface import (  # noqa: E402
    KERNEL_COMMIT,
    KERNEL_TAG,
    KERNEL_TAG_OBJECT,
    RELEASE_WHEEL_SHA256,
    SCHEMA_SHA256,
)

EXPECTED_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "tag",
        "annotated_tag_object",
        "commit",
        "package_version",
        "plugin_version",
        "expected_release_wheel_sha256",
        "files",
        "interface_sha256",
    }
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _load_canonical(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SystemExit(f"duplicate manifest key: {key}")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if (
        not isinstance(value, dict)
        or raw
        != (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    ):
        raise SystemExit("kernel release interface manifest is not canonical")
    return value


def verify_interface(interface: Path) -> str:
    interface = interface.resolve()
    manifest_path = interface / "kernel-release-interface.json"
    manifest_mode = manifest_path.lstat().st_mode
    if manifest_path.is_symlink() or not stat.S_ISREG(manifest_mode):
        raise SystemExit("kernel release interface manifest is not a regular file")
    manifest = _load_canonical(manifest_path)
    if set(manifest) != EXPECTED_KEYS:
        raise SystemExit("kernel release interface manifest shape is open")
    expected_identity = {
        "schema_version": "1.0.0",
        "repository": "mingjiconnect-ctrl/owner-valuation-kernel",
        "tag": KERNEL_TAG,
        "annotated_tag_object": KERNEL_TAG_OBJECT,
        "commit": KERNEL_COMMIT,
        "package_version": "2.0.0rc2",
        "plugin_version": "2.0.0-rc.2",
        "expected_release_wheel_sha256": RELEASE_WHEEL_SHA256,
    }
    if any(manifest.get(key) != value for key, value in expected_identity.items()):
        raise SystemExit("kernel release interface identity drifted")
    files = manifest.get("files")
    if (
        not isinstance(files, dict)
        or not files
        or list(files) != sorted(files)
        or any(
            not isinstance(relative, str)
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or not isinstance(digest, str)
            or len(digest) != 64
            for relative, digest in files.items()
        )
    ):
        raise SystemExit("kernel release interface file map is malformed")
    actual_files: set[str] = set()
    for root, directories, filenames in os.walk(interface, followlinks=False):
        root_path = Path(root)
        for directory in tuple(directories):
            path = root_path / directory
            mode = path.lstat().st_mode
            if path.is_symlink() or not stat.S_ISDIR(mode):
                raise SystemExit(
                    "kernel release interface contains a non-directory path: "
                    f"{path.relative_to(interface).as_posix()}"
                )
        for filename in filenames:
            path = root_path / filename
            relative = path.relative_to(interface).as_posix()
            mode = path.lstat().st_mode
            if path.is_symlink() or not stat.S_ISREG(mode):
                raise SystemExit(
                    f"kernel release interface contains a non-regular file: {relative}"
                )
            if relative == "kernel-release-interface.json":
                continue
            if ".git" in path.parts or "tests" in path.parts or "docs" in path.parts:
                raise SystemExit(f"kernel release interface exposes a forbidden tree: {relative}")
            actual_files.add(relative)
            if hashlib.sha256(path.read_bytes()).hexdigest() != files.get(relative):
                raise SystemExit(f"kernel release interface file hash drifted: {relative}")
    if actual_files != set(files):
        raise SystemExit("kernel release interface file inventory is not exact")
    for name, digest in SCHEMA_SHA256.items():
        if files.get(f"kernel/schemas/{name}") != digest:
            raise SystemExit(f"kernel release interface schema is missing or wrong: {name}")
    unsigned = dict(manifest)
    reported = unsigned.pop("interface_sha256")
    if reported != _canonical_sha256(unsigned):
        raise SystemExit("kernel release interface self-hash does not replay")
    return str(reported)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", type=Path, required=True)
    args = parser.parse_args()
    print(verify_interface(args.interface))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
