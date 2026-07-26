#!/usr/bin/env python3
"""Verify the clean public root and its content-addressed private provenance."""

from __future__ import annotations

from public_bootstrap import verify_public_bootstrap_snapshot


def main() -> int:
    payload = verify_public_bootstrap_snapshot()
    source = payload["private_source"]
    destination = payload["public_destination"]
    print(
        "Public bootstrap verified: "
        f"{source['commit']}:{source['tree']} -> {destination['repository']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

