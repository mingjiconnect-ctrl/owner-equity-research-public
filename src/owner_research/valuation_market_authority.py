"""Load and independently verify the wheel-owned Phase 5E-1.1 market authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .component_lock import default_component_lock_path, load_component_lock
from .fingerprints import canonical_sha256
from .valuation_market_authority_types import (
    MarketAccessAuthority,
    MarketProviderRegistration,
    MarketProviderRegistry,
    TradingCalendarDataset,
    TradingCalendarRegistry,
    TradingSession,
)

_PACKAGE_ROOT = Path(__file__).resolve().parent


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resource(path: str, expected_sha256: str) -> tuple[Path, dict[str, Any]]:
    candidate = (_PACKAGE_ROOT / path).resolve()
    if _PACKAGE_ROOT not in candidate.parents or not candidate.is_file():
        raise ValueError("market authority resource is unavailable")
    if _file_sha256(candidate) != expected_sha256:
        raise ValueError("market authority resource hash mismatch")
    payload = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("market authority resource must be a JSON object")
    return candidate, payload


def _provider_registry(section: dict[str, Any]) -> MarketProviderRegistry:
    path, payload = _resource(section["path"], section["sha256"])
    registrations = tuple(MarketProviderRegistration(**item) for item in payload["registrations"])
    for registration in registrations:
        module_path = _PACKAGE_ROOT / registration.adapter_module
        parser_path = _PACKAGE_ROOT / registration.parser_module
        if _file_sha256(module_path) != registration.adapter_sha256:
            raise ValueError("registered adapter code hash mismatch")
        if _file_sha256(parser_path) != registration.parser_sha256:
            raise ValueError("registered parser code hash mismatch")
    registry = MarketProviderRegistry(
        registry_id=payload["registry_id"],
        registry_version=payload["registry_version"],
        registrations=registrations,
    )
    if path.name != "provider-registry.json":
        raise ValueError("provider registry resource identity mismatch")
    return registry


def _calendar_registry(section: dict[str, Any]) -> TradingCalendarRegistry:
    _path, payload = _resource(section["path"], section["sha256"])
    datasets: list[TradingCalendarDataset] = []
    for record in payload["datasets"]:
        dataset_path, dataset_payload = _resource(
            record["dataset_path"], record["dataset_sha256"]
        )
        source_path, _source_payload = _resource(
            record["source_record_path"], record["source_record_sha256"]
        )
        if dataset_payload["official_source_record_sha256"] != record["source_record_sha256"]:
            raise ValueError("calendar dataset source hash mismatch")
        sessions = tuple(TradingSession(**item) for item in dataset_payload.pop("sessions"))
        dataset = TradingCalendarDataset(
            **dataset_payload,
            sessions=sessions,
            dataset_sha256=record["dataset_sha256"],
        )
        if (
            dataset.mic != record["mic"]
            or dataset.calendar_id != record["calendar_id"]
            or dataset_path.suffix != ".json"
            or source_path.suffix != ".json"
        ):
            raise ValueError("calendar registry identity mismatch")
        datasets.append(dataset)
    return TradingCalendarRegistry(
        registry_id=payload["registry_id"],
        registry_version=payload["registry_version"],
        datasets=tuple(datasets),
    )


def load_market_access_authority(
    component_lock_path: Path | None = None,
) -> MarketAccessAuthority:
    lock_path = Path(component_lock_path or default_component_lock_path())
    lock = load_component_lock(lock_path)
    if lock.get("lock_version") not in {"1.1.0", "1.2.0"}:
        raise ValueError("market authority requires a compatible component lock")
    section = lock.get("market_access_authority")
    if not isinstance(section, dict) or section.get("authority_version") != "1.0.0":
        raise ValueError("component lock lacks the Phase 5E-1.1 market authority")
    security_path, _security = _resource(
        section["security_identity_policy"]["path"],
        section["security_identity_policy"]["sha256"],
    )
    secret_path, _secret = _resource(
        section["secret_policy"]["path"], section["secret_policy"]["sha256"]
    )
    if (
        security_path.name != "security-identity-policy.json"
        or secret_path.name != "secret-policy.json"
    ):
        raise ValueError("market authority policy identity mismatch")
    return MarketAccessAuthority(
        lock_version="1.1.0",
        authority_version=section["authority_version"],
        provider_registry=_provider_registry(section["provider_registry"]),
        calendar_registry=_calendar_registry(section["calendar_registry"]),
        security_policy_sha256=section["security_identity_policy"]["sha256"],
        secret_policy_sha256=section["secret_policy"]["sha256"],
        authority_sha256=canonical_sha256(section),
    )


__all__ = ()
