#!/usr/bin/env python3
"""Protected-base scanner for candidate Python startup and import-shadow surfaces."""

from __future__ import annotations

import argparse
import importlib.machinery
import stat
import sys
from pathlib import Path

_THIRD_PARTY_ROOTS = frozenset(
    {
        "_distutils_hack",
        "_pytest",
        "anyio",
        "attr",
        "attrs",
        "certifi",
        "exceptiongroup",
        "h11",
        "hatchling",
        "httpcore",
        "httpx",
        "idna",
        "iniconfig",
        "jsonschema",
        "jsonschema_specifications",
        "lxml",
        "packaging",
        "pathspec",
        "pip",
        "pluggy",
        "pygments",
        "pytest",
        "referencing",
        "rpds",
        "ruff",
        "setuptools",
        "tomli",
        "trove_classifiers",
        "typing_extensions",
        "wheel",
        "yaml",
    }
)
_STARTUP_ROOTS = frozenset({"sitecustomize", "usercustomize"})
_FORBIDDEN_FILE_SUFFIXES = (".pth", ".egg-link")


def _module_name(path: Path) -> str | None:
    if path.is_dir():
        return path.name
    name = path.name
    # Recognize extension modules before consulting the host suffix registry: a host may know the
    # generic ``.so`` suffix yet not the candidate's foreign ABI tag.
    lowered = name.casefold()
    for extension in (".so", ".pyd", ".dylib"):
        if lowered.endswith(extension):
            return name[: -len(extension)].split(".", 1)[0]
    for suffix in sorted(importlib.machinery.all_suffixes(), key=len, reverse=True):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return None


def verify(repository: Path) -> None:
    repository = repository.resolve(strict=True)
    roots = (repository, repository / "src", repository / "scripts", repository / "tests")
    denied = frozenset(sys.stdlib_module_names) | _THIRD_PARTY_ROOTS | _STARTUP_ROOTS
    findings: list[str] = []
    for root in roots:
        if not root.is_dir():
            findings.append(f"missing active import root: {root.relative_to(repository)}")
            continue
        entries = root.iterdir() if root == repository else root.rglob("*")
        for path in sorted(entries, key=lambda item: item.as_posix()):
            relative = path.relative_to(repository).as_posix()
            mode = path.lstat().st_mode
            if path.is_symlink() or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                findings.append(f"unsafe import entry type: {relative}")
                continue
            lower_name = path.name.lower()
            if lower_name == "pyvenv.cfg" or lower_name.endswith(_FORBIDDEN_FILE_SUFFIXES):
                findings.append(f"forbidden Python path-control file: {relative}")
            module_name = _module_name(path)
            cached_startup = path.parent.name == "__pycache__" and any(
                path.name.startswith(name + ".") for name in _STARTUP_ROOTS
            )
            if module_name in _STARTUP_ROOTS or cached_startup:
                findings.append(f"forbidden Python startup hook: {relative}")
        for child in sorted(root.iterdir(), key=lambda item: item.name):
            module_name = _module_name(child)
            if module_name in denied:
                findings.append(
                    f"candidate import root shadows protected module {module_name}: "
                    f"{child.relative_to(repository).as_posix()}"
                )
    if findings:
        raise SystemExit("\n".join(sorted(set(findings))))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    verify(args.repository)
    print("candidate startup and import-shadow surface verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
