#!/usr/bin/env python3
"""Generate explicit UTC session datasets from reviewed official 2026 source records."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = ROOT / "src/owner_research/resources/market_access"
UTC = ZoneInfo("UTC")


def _canonical(payload: object) -> bytes:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (text + "\n").encode()


def _generate(source_path: Path) -> tuple[Path, str, str]:
    source_bytes = source_path.read_bytes()
    source = json.loads(source_bytes)
    timezone = ZoneInfo(source["timezone"])
    closed = set(source["closed_dates"])
    early = source["early_closes"]
    current = date(source["year"], 1, 1)
    end = date(source["year"], 12, 31)
    sessions: list[dict[str, object]] = []
    while current <= end:
        text = current.isoformat()
        if current.weekday() < 5 and text not in closed:
            open_hour, open_minute = map(int, source["regular_open"].split(":"))
            close_hour, close_minute = map(
                int, early.get(text, source["regular_close"]).split(":")
            )
            opened = datetime.combine(
                current, time(open_hour, open_minute), timezone
            ).astimezone(UTC)
            closed_at = datetime.combine(
                current, time(close_hour, close_minute), timezone
            ).astimezone(UTC)
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
    payload = {
        "calendar_id": f"calendar:{source['mic']}:2026:1.0.0",
        "mic": source["mic"],
        "timezone": source["timezone"],
        "coverage_start": f"{source['year']}-01-01",
        "coverage_end": f"{source['year']}-12-31",
        "official_source_url": source["official_source_url"],
        "official_source_record_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "sessions": sessions,
    }
    output = RESOURCE / "calendars" / f"{source['mic']}-2026.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical(payload)
    output.write_bytes(data)
    return output, hashlib.sha256(data).hexdigest(), hashlib.sha256(source_bytes).hexdigest()


def main() -> int:
    datasets = []
    for source_path in sorted((RESOURCE / "calendar_sources").glob("*.json")):
        output, dataset_sha, source_sha = _generate(source_path)
        payload = json.loads(output.read_text())
        datasets.append(
            {
                "mic": payload["mic"],
                "calendar_id": payload["calendar_id"],
                "dataset_path": output.relative_to(ROOT / "src/owner_research").as_posix(),
                "dataset_sha256": dataset_sha,
                "source_record_path": source_path.relative_to(
                    ROOT / "src/owner_research"
                ).as_posix(),
                "source_record_sha256": source_sha,
            }
        )
    registry = {
        "registry_id": "trading-calendar-registry",
        "registry_version": "1.0.0",
        "datasets": datasets,
    }
    (RESOURCE / "calendar-registry.json").write_bytes(_canonical(registry))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
