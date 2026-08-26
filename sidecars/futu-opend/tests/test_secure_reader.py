from __future__ import annotations

import os
from pathlib import Path

import pytest

import owner_research_futu_sidecar.secure_reader as secure_reader_module
from owner_research_futu_sidecar.secure_reader import (
    ReadBudget,
    SecureReadError,
    read_bounded_snapshot,
)


def test_secure_reader_rejects_oversize_symlink_and_hardlink(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123456789")
    with pytest.raises(SecureReadError, match="per-file"):
        read_bounded_snapshot(source, maximum_bytes=4)

    symlink = tmp_path / "source-link.bin"
    symlink.symlink_to(source)
    with pytest.raises(SecureReadError, match="non-linked"):
        read_bounded_snapshot(symlink, maximum_bytes=100)

    hardlink = tmp_path / "source-hardlink.bin"
    os.link(source, hardlink)
    with pytest.raises(SecureReadError, match="non-linked"):
        read_bounded_snapshot(source, maximum_bytes=100)


def test_secure_reader_rejects_growth_and_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    growing = tmp_path / "growing.bin"
    growing.write_bytes(b"a" * (1024 * 1024 + 10))
    real_read = secure_reader_module.os.read
    changed = False

    def growing_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        value = real_read(descriptor, count)
        if not changed:
            changed = True
            with growing.open("ab") as stream:
                stream.write(b"growth")
        return value

    monkeypatch.setattr(secure_reader_module.os, "read", growing_read)
    with pytest.raises(SecureReadError, match="changed"):
        read_bounded_snapshot(growing, maximum_bytes=2 * 1024 * 1024)

    monkeypatch.setattr(secure_reader_module.os, "read", real_read)
    original = tmp_path / "replace.bin"
    replacement = tmp_path / "replacement.bin"
    original.write_bytes(b"original")
    replacement.write_bytes(b"replacement")
    replaced = False

    def replacing_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        value = real_read(descriptor, count)
        if not replaced:
            replaced = True
            os.replace(replacement, original)
        return value

    monkeypatch.setattr(secure_reader_module.os, "read", replacing_read)
    with pytest.raises(SecureReadError, match="changed|rebound"):
        read_bounded_snapshot(original, maximum_bytes=1024)


def test_secure_reader_cumulative_budget(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1234")
    second.write_bytes(b"5678")
    budget = ReadBudget(maximum_bytes=7)
    assert read_bounded_snapshot(first, maximum_bytes=10, budget=budget) == b"1234"
    with pytest.raises(SecureReadError, match="cumulative"):
        read_bounded_snapshot(second, maximum_bytes=10, budget=budget)
