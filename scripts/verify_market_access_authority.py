#!/usr/bin/env python3
"""Independent Phase 5E-1.1 authority oracle.

This verifier intentionally does not import the production authority loader, parser, adapter, or
calendar selector. It re-hashes files and reconstructs every expected 2026 session itself.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from datetime import date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src/owner_research"
LOCK = ROOT / "component-lock.json"
SECRET_PATTERN = re.compile(
    r"(?i)(authorization\s*:|bearer\s+|api[_-]?key=|token=|secret=|password=|https?://[^/\s]+@)"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resource(record: dict[str, str]) -> tuple[Path, dict]:
    path = (PACKAGE / record["path"]).resolve()
    if PACKAGE not in path.parents or not path.is_file():
        raise ValueError(f"authority resource unavailable: {record['path']}")
    if _sha(path) != record["sha256"]:
        raise ValueError(f"authority resource hash mismatch: {record['path']}")
    return path, json.loads(path.read_text(encoding="utf-8"))


def _locked_file(record: dict[str, str]) -> Path:
    path = (PACKAGE / record["path"]).resolve()
    if PACKAGE not in path.parents or not path.is_file():
        raise ValueError(f"authority file unavailable: {record['path']}")
    if _sha(path) != record["sha256"]:
        raise ValueError(f"authority file hash mismatch: {record['path']}")
    return path


def _assert_symbol(path: Path, symbol: str, expected_kind: type[ast.AST]) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    matches = [node for node in tree.body if getattr(node, "name", None) == symbol]
    if len(matches) != 1 or not isinstance(matches[0], expected_kind):
        raise ValueError(f"locked symbol is missing or ambiguous: {path.name}:{symbol}")


def _expected_sessions(source: dict) -> list[dict[str, object]]:
    timezone = ZoneInfo(source["timezone"])
    utc = ZoneInfo("UTC")
    current = date(source["year"], 1, 1)
    end = date(source["year"], 12, 31)
    closed = set(source["closed_dates"])
    early = source["early_closes"]
    sessions = []
    while current <= end:
        text = current.isoformat()
        if current.weekday() < 5 and text not in closed:
            open_hour, open_minute = map(int, source["regular_open"].split(":"))
            close_hour, close_minute = map(
                int, early.get(text, source["regular_close"]).split(":")
            )
            opened = datetime.combine(
                current, time(open_hour, open_minute), timezone
            ).astimezone(utc)
            closed_at = datetime.combine(
                current, time(close_hour, close_minute), timezone
            ).astimezone(utc)
            sessions.append(
                {
                    "mic": source["mic"],
                    "trading_date": text,
                    "opened_at": opened.isoformat().replace("+00:00", "Z"),
                    "closed_at": closed_at.isoformat().replace("+00:00", "Z"),
                    "early_close": text in early,
                }
            )
        current += timedelta(days=1)
    return sessions


def verify() -> tuple[str, ...]:
    errors: list[str] = []
    try:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        if lock.get("lock_version") not in {"1.1.0", "1.2.0"}:
            raise ValueError("component-lock version is not an approved authority container")
        authority = lock["market_access_authority"]
        if authority.get("authority_version") != "1.0.0":
            raise ValueError("market authority version mismatch")
        provider_path, providers = _resource(authority["provider_registry"])
        calendar_path, calendars = _resource(authority["calendar_registry"])
        _resource(authority["security_identity_policy"])
        _resource(authority["secret_policy"])
        adapter_path = _locked_file(authority["adapter_code"])
        parser_path = _locked_file(authority["parser_code"])
        if (
            provider_path.name != "provider-registry.json"
            or calendar_path.name != "calendar-registry.json"
        ):
            raise ValueError("authority registry filenames changed")
        identities: set[tuple[str, str]] = set()
        for registration in providers["registrations"]:
            identity = (registration["provider_id"], registration["provider_version"])
            if identity in identities:
                raise ValueError("duplicate provider registration")
            identities.add(identity)
            if registration["adapter_sha256"] != _sha(adapter_path):
                raise ValueError("registration adapter SHA mismatch")
            if registration["parser_sha256"] != _sha(parser_path):
                raise ValueError("registration parser SHA mismatch")
            if registration["adapter_kind"] not in {"recorded", "loopback"}:
                raise ValueError("live adapter registered during Phase 5E-1.1")
            _assert_symbol(
                adapter_path,
                registration["adapter_class"].rsplit(".", 1)[1],
                ast.ClassDef,
            )
            _assert_symbol(
                parser_path,
                registration["parser_function"].rsplit(".", 1)[1],
                ast.FunctionDef,
            )
        if not identities:
            raise ValueError("authority has no provider registrations")
        for record in calendars["datasets"]:
            dataset_path, dataset = _resource(
                {"path": record["dataset_path"], "sha256": record["dataset_sha256"]}
            )
            _source_path, source = _resource(
                {
                    "path": record["source_record_path"],
                    "sha256": record["source_record_sha256"],
                }
            )
            if dataset["official_source_record_sha256"] != record["source_record_sha256"]:
                raise ValueError("calendar source receipt hash mismatch")
            if dataset["sessions"] != _expected_sessions(source):
                raise ValueError(f"calendar sessions do not replay: {dataset_path.name}")
        if {item["mic"] for item in calendars["datasets"]} != {"XNYS", "XNAS"}:
            raise ValueError("calendar authority does not cover exactly XNYS/XNAS")
        for path in (
            LOCK,
            provider_path,
            calendar_path,
            adapter_path,
            parser_path,
        ):
            text = path.read_text(encoding="utf-8")
            if SECRET_PATTERN.search(text):
                raise ValueError(f"secret-like material appears in authority surface: {path.name}")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    return tuple(errors)


def main() -> int:
    errors = verify()
    for error in errors:
        print(error)
    if errors:
        return 1
    print("Phase 5E-1.1 independent market authority verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
