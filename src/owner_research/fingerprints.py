from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Any


def to_json_value(value: Any) -> Any:
    """Return a detached JSON-compatible value without mutating the source."""
    if isinstance(value, FrozenMap):
        return {key: to_json_value(item) for key, item in value.items()}
    if is_dataclass(value):
        return {field.name: to_json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): to_json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [to_json_value(item) for item in value]
    if isinstance(value, list):
        return [to_json_value(item) for item in value]
    if isinstance(value, Decimal):
        return str(value)
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        to_json_value(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class FrozenMap(Mapping[str, Any]):
    """Small immutable mapping used inside frozen contract dataclasses."""

    __slots__ = ("_items", "_index")

    def __init__(self, values: Mapping[str, Any]) -> None:
        items = tuple(sorted((str(key), freeze(item)) for key, item in values.items()))
        object.__setattr__(self, "_items", items)
        object.__setattr__(self, "_index", MappingProxyType(dict(items)))

    def __getitem__(self, key: str) -> Any:
        return self._index[key]

    def __iter__(self):
        return iter(self._index)

    def __len__(self) -> int:
        return len(self._index)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("FrozenMap is immutable")

    def __repr__(self) -> str:
        return f"FrozenMap({dict(self._items)!r})"


def freeze(value: Any) -> Any:
    if isinstance(value, FrozenMap):
        return value
    if isinstance(value, Mapping):
        return FrozenMap(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(freeze(item) for item in value)
    return value
