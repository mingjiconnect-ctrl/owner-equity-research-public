"""Pytest plugin that binds each JUnit testcase to its exact executed node ID."""

from __future__ import annotations

from typing import Any


def pytest_runtest_setup(item: Any) -> None:
    item.user_properties.append(("phase5e_nodeid", item.nodeid))
