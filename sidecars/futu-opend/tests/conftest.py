from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_pinned_sdk_imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep each real-SDK test import inside one disposable owner-only HOME."""

    private_home = tmp_path / "test-sdk-import-home"
    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(private_home))
    monkeypatch.setenv("XDG_CACHE_HOME", os.fspath(private_home / ".cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", os.fspath(private_home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", os.fspath(private_home / ".local" / "share"))
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    sys.dont_write_bytecode = True
    yield
    module = sys.modules.get("futu.common.ft_logger")
    logger = getattr(module, "logger", None)
    if logger is not None:
        for target_name in ("file_logger", "console_logger"):
            target = getattr(logger, target_name, None)
            if not isinstance(target, logging.Logger):
                continue
            for handler in tuple(target.handlers):
                target.removeHandler(handler)
                handler.close()
    for name in tuple(sys.modules):
        if name == "futu" or name.startswith("futu."):
            sys.modules.pop(name, None)
