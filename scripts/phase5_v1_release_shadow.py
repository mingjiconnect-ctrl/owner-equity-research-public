#!/usr/bin/env python3
"""Record the non-release-qualifying Phase 5 code-complete preview shadow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from owner_research import __version__
from owner_research.component_lock import (
    default_component_lock_path,
    file_sha256,
    read_stable_file_bytes,
)
from owner_research.fingerprints import canonical_json, canonical_sha256

ROOT = Path(__file__).resolve().parents[1]
CUTOFF = "2026-07-11"
EVALUATED_AT = "2026-08-14T12:00:00Z"
SOURCES = (
    ("union_pacific", "issuer:union-pacific", "business-quality-union-pacific.json"),
    ("salesforce", "issuer:salesforce", "business-quality-salesforce.json"),
)


class ReleaseShadowError(ValueError):
    """The ordered release shadow cannot be reproduced from frozen metadata."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_source(path: Path, expected_issuer: str) -> tuple[dict[str, Any], str]:
    try:
        raw = read_stable_file_bytes(path, maximum_size=16 * 1024 * 1024)
    except (OSError, ValueError) as exc:
        raise ReleaseShadowError(f"shadow source is unavailable: {path.name}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseShadowError(f"shadow source is invalid JSON: {path.name}") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("issuer_id") != expected_issuer
        or payload.get("data_cutoff_date") != CUTOFF
        or payload.get("review_status") != "blocked"
        or payload.get("network_access_performed") is not False
        or payload.get("contains_market_price") is not False
        or payload.get("contains_valuation") is not False
        or not isinstance(payload.get("blocked_items"), list)
        or not payload["blocked_items"]
    ):
        raise ReleaseShadowError(f"shadow source boundary drifted: {path.name}")
    return payload, _sha256(raw)


def build_release_shadow() -> dict[str, Any]:
    """Build the ordered UNP then Salesforce fail-closed preview evidence."""

    shadow_root = ROOT / "evals" / "shadow" / CUTOFF
    attempts: list[dict[str, Any]] = []
    for order, (label, issuer_id, filename) in enumerate(SOURCES, start=1):
        source, source_sha256 = _load_source(shadow_root / filename, issuer_id)
        issue_codes = tuple(
            sorted(
                {
                    *source["blocked_items"],
                    "canonical_research_bundle_unavailable",
                    "price_blind_valuation_freeze_unavailable",
                }
            )
        )
        attempts.append(
            {
                "attempt": order,
                "issuer_label": label,
                "issuer_id": issuer_id,
                "source_shadow_path": f"evals/shadow/{CUTOFF}/{filename}",
                "source_shadow_sha256": source_sha256,
                "source_verification_mode": source["source_verification_mode"],
                "official_source_ids": [
                    item["source_identifier"] for item in source["official_filings"]
                ],
                "status": "blocked",
                "stopped_before": "market_reference",
                "issue_codes": issue_codes,
                "market_provider_invoked": False,
                "kernel_invoked": False,
                "archive_written": False,
            }
        )
    core: dict[str, Any] = {
        "schema_version": "1.0.0",
        "shadow_type": "phase5-v1-code-complete-preview-sequential-external",
        "data_cutoff_date": CUTOFF,
        "evaluated_at": EVALUATED_AT,
        "attempt_policy": "union_pacific_then_salesforce_if_insufficient",
        "attempts": attempts,
        "overall_status": "blocked",
        "release_qualifying": False,
        "rc_tag_permitted": False,
        "real_futu_opend_canary_completed": False,
        "component_lock_sha256": file_sha256(default_component_lock_path()),
        "owner_equity_research_version": __version__,
        "network_access_performed": False,
        "contains_raw_source_content": False,
        "contains_market_price": False,
        "contains_valuation_request": False,
        "contains_valuation_result": False,
        "contains_kernel_stdout": False,
        "contains_archive": False,
        "fallback_reason": "union_pacific_evidence_insufficient_for_price_blind_freeze",
    }
    core["shadow_fingerprint"] = canonical_sha256(core)
    return core


def write_release_shadow(output: Path) -> Path:
    payload = build_release_shadow()
    content = (canonical_json(payload) + "\n").encode("utf-8")
    target = Path(output).expanduser().absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = read_stable_file_bytes(target, maximum_size=16 * 1024 * 1024)
    except FileNotFoundError:
        existing = None
    except (OSError, ValueError) as exc:
        raise ReleaseShadowError(
            "release shadow output is not one bounded regular non-symlink file"
        ) from exc
    if existing is not None:
        if existing == content:
            return target
        raise ReleaseShadowError("release shadow output exists with different content")
    temporary = target.parent / f".{target.name}.staging-{uuid.uuid4().hex}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ReleaseShadowError("release shadow write did not complete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, target, follow_symlinks=False)
    except FileExistsError as exc:
        try:
            raced_content = read_stable_file_bytes(
                target,
                maximum_size=16 * 1024 * 1024,
            )
        except (OSError, ValueError) as read_exc:
            temporary.unlink(missing_ok=True)
            raise ReleaseShadowError(
                "release shadow output appeared with unsafe content"
            ) from read_exc
        temporary.unlink(missing_ok=True)
        if raced_content == content:
            return target
        raise ReleaseShadowError(
            "release shadow output appeared with different content"
        ) from exc
    temporary.unlink()
    parent_descriptor = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_release_shadow(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
