from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import owner_research.valuation_assumption_ledger as assumption_module
import owner_research.valuation_fact_mapping as fact_module
import owner_research.valuation_final_request as final_module


def _forbid_path_reopen(*_args: object, **_kwargs: object) -> bytes:
    raise AssertionError("caller-selected input was reopened through pathlib")


def test_pinned_kernel_schema_loaders_hash_and_parse_one_bounded_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = b"{}\n"
    digest = hashlib.sha256(raw).hexdigest()
    schema_directory = tmp_path / "schemas"
    schema_directory.mkdir()
    (schema_directory / "fact-ledger.schema.json").write_bytes(raw)
    (schema_directory / "assumption-ledger.schema.json").write_bytes(raw)

    monkeypatch.setattr(fact_module, "_git", lambda *_args: fact_module.KERNEL_COMMIT)
    monkeypatch.setattr(fact_module, "PINNED_FACT_LEDGER_SCHEMA_SHA256", digest)
    monkeypatch.setattr(
        assumption_module,
        "_git",
        lambda *_args: assumption_module.PINNED_KERNEL_COMMIT,
    )
    monkeypatch.setattr(assumption_module, "KERNEL_ASSUMPTION_SCHEMA_SHA256", digest)
    monkeypatch.setattr(Path, "read_text", _forbid_path_reopen)
    monkeypatch.setattr(Path, "read_bytes", _forbid_path_reopen)

    assert fact_module._load_kernel_fact_schema(tmp_path) == {}
    assert assumption_module._load_assumption_schema(tmp_path) == {}


def test_final_request_schema_loader_never_hashes_then_reopens_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = b"{}\n"
    digest = hashlib.sha256(raw).hexdigest()
    schema_hashes = {
        "schemas/fact-ledger.schema.json": digest,
        "schemas/assumption-ledger.schema.json": digest,
        "schemas/valuation-request.schema.json": digest,
    }
    for relative in schema_hashes:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def fake_git(_repository: Path, *args: str) -> str:
        if args == ("rev-parse", "HEAD") or args == (
            "rev-parse",
            f"{final_module.PINNED_KERNEL_TAG}^{{}}",
        ):
            return final_module.PINNED_KERNEL_COMMIT
        if args == ("rev-parse", f"refs/tags/{final_module.PINNED_KERNEL_TAG}"):
            return "tag-object"
        raise AssertionError(args)

    monkeypatch.setattr(final_module, "_git", fake_git)
    monkeypatch.setattr(final_module, "_KERNEL_TAG_OBJECT", "tag-object")
    monkeypatch.setattr(final_module, "PINNED_KERNEL_SCHEMA_SHA256", schema_hashes)
    monkeypatch.setattr(Path, "read_text", _forbid_path_reopen)
    monkeypatch.setattr(Path, "read_bytes", _forbid_path_reopen)

    _kernel, schemas = final_module._verify_kernel(tmp_path)
    assert schemas == {relative: {} for relative in sorted(schema_hashes)}
