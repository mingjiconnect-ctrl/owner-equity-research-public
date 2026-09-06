from __future__ import annotations

import json
from pathlib import Path

import pytest

import owner_research.valuation_synthesis_types as schema_module
from owner_research.fingerprints import canonical_json
from owner_research.valuation_synthesis_types import ExtensionAuthorityError


def _clear_schema_caches() -> None:
    schema_module._extension_schema_set.cache_clear()
    schema_module._extension_registry.cache_clear()
    schema_module._extension_validator.cache_clear()


@pytest.fixture(autouse=True)
def _isolated_schema_caches() -> None:
    _clear_schema_caches()
    yield
    _clear_schema_caches()


def _write_schema_set(directory: Path, *, first_bytes: bytes | None = None) -> None:
    directory.mkdir()
    for index, name in enumerate(schema_module.EXTENSION_SCHEMA_NAMES):
        payload = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://example.invalid/{name}.schema.json",
            "type": "object",
            "additionalProperties": False,
        }
        raw = (
            first_bytes
            if index == 0 and first_bytes is not None
            else (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        )
        (directory / f"{name}.schema.json").write_bytes(raw)


def _redirect(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    monkeypatch.setattr(schema_module, "extension_schema_directory", lambda: directory)
    _clear_schema_caches()


def test_extension_schema_loader_normalizes_trusted_json_and_returns_fresh_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "schemas"
    _write_schema_set(directory)
    _redirect(monkeypatch, directory)
    name = schema_module.EXTENSION_SCHEMA_NAMES[0]

    first = schema_module.load_extension_schema(name)
    assert canonical_json(first) == canonical_json(schema_module.load_extension_schema(name))
    first["type"] = "array"
    assert schema_module.load_extension_schema(name)["type"] == "object"


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (b'{"type":"object","type":"array"}', "repeats key"),
        (b'{"type":"object","maximum":NaN}', "non-finite"),
    ),
)
def test_extension_schema_loader_rejects_ambiguous_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    directory = tmp_path / "schemas"
    _write_schema_set(directory, first_bytes=raw)
    _redirect(monkeypatch, directory)

    with pytest.raises(ExtensionAuthorityError, match=message):
        schema_module.load_extension_schema(schema_module.EXTENSION_SCHEMA_NAMES[0])


def test_extension_schema_loader_rejects_symlink_and_per_file_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "schemas"
    _write_schema_set(directory)
    name = schema_module.EXTENSION_SCHEMA_NAMES[0]
    source = directory / f"{name}.schema.json"
    target = tmp_path / "outside.schema.json"
    target.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(target)
    _redirect(monkeypatch, directory)
    with pytest.raises(ExtensionAuthorityError, match="unavailable"):
        schema_module.load_extension_schema(name)

    source.unlink()
    source.write_bytes(target.read_bytes())
    monkeypatch.setattr(schema_module, "EXTENSION_SCHEMA_MAX_BYTES", 4)
    _clear_schema_caches()
    with pytest.raises(ExtensionAuthorityError, match="bounded regular file"):
        schema_module.load_extension_schema(name)


def test_extension_schema_loader_enforces_cumulative_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "schemas"
    _write_schema_set(directory)
    _redirect(monkeypatch, directory)
    first = directory / f"{schema_module.EXTENSION_SCHEMA_NAMES[0]}.schema.json"
    monkeypatch.setattr(schema_module, "EXTENSION_SCHEMA_MAX_BYTES", 16 * 1024 * 1024)
    monkeypatch.setattr(
        schema_module,
        "EXTENSION_SCHEMA_TOTAL_MAX_BYTES",
        len(first.read_bytes()),
    )
    _clear_schema_caches()

    with pytest.raises(ExtensionAuthorityError, match="cumulative byte limit"):
        schema_module.load_extension_schema(schema_module.EXTENSION_SCHEMA_NAMES[0])
