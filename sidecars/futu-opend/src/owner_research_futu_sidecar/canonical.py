from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class SidecarContractError(ValueError):
    """Raised when an untrusted value violates a closed sidecar contract."""


def expected_resolved_local_path(path: Path) -> Path:
    """Return the physical spelling of a path after a trusted Darwin root alias.

    Darwin exposes fixed root-owned aliases such as ``/tmp -> /private/tmp``.
    They are part of the platform filesystem layout, not caller-controlled path
    rebinding.  Only that exact first component is normalized; a later symlink
    still makes ``Path.resolve()`` differ from this expected identity.
    """

    absolute = Path(path).expanduser().absolute()
    if (
        sys.platform == "darwin"
        and len(absolute.parts) >= 2
        and absolute.parts[1] in {"etc", "tmp", "var"}
    ):
        root_alias = Path(absolute.anchor) / absolute.parts[1]
        expected_target = Path("/private") / absolute.parts[1]
        try:
            alias_details = root_alias.lstat()
            alias_target = root_alias.resolve(strict=True)
        except OSError:
            pass
        else:
            if (
                stat.S_ISLNK(alias_details.st_mode)
                and alias_details.st_uid == 0
                and alias_target == expected_target
                and alias_target.is_dir()
            ):
                return alias_target.joinpath(*absolute.parts[2:])
    return absolute


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_sha256(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise SidecarContractError("SHA-256 input must be exact bytes")
    return hashlib.sha256(value).hexdigest()


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SidecarContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_exact_members(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SidecarContractError(f"{label} has an unexpected member set")
    return value


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SidecarContractError(f"duplicate JSON member is forbidden: {key}")
        result[key] = value
    return result


def load_canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise SidecarContractError(f"{label} must be bytes")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SidecarContractError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or text != canonical_json(value):
        raise SidecarContractError(f"{label} must be one canonical JSON object")
    return value


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def signed_identity(prefix: str, values: Mapping[str, Any]) -> str:
    unsigned = dict(values)
    unsigned.pop("receipt_id", None)
    unsigned.pop("signature_hex", None)
    return f"{prefix}{canonical_sha256(unsigned)}"
