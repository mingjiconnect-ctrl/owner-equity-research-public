#!/usr/bin/env python3
"""Retired single-runtime Phase 5E report writer.

Protected audits now publish only the independently verified three-runtime manifest produced by
``verify_phase5e_audit_runtime_matrix.py``.  Keeping this fail-closed shim preserves historical
path references without retaining a second report format that could expose raw findings, JUnit,
or node-id hashes.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reviewed-commit")
    parser.add_argument("--started-at")
    parser.add_argument("--ci-run-id", action="append")
    parser.add_argument("--findings-file", type=Path)
    parser.parse_args()
    parser.error(
        "single-runtime audit reports are retired; use "
        "verify_phase5e_audit_runtime_matrix.py"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
