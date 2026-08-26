from __future__ import annotations

import socket
import struct
from typing import Any

from .canonical import SidecarContractError, canonical_bytes, load_canonical_json

WIRE_SCHEMA_VERSION = "2.0.0"
MAXIMUM_REQUEST_BYTES = 1024 * 1024
MAXIMUM_RESPONSE_BYTES = 16 * 1024 * 1024
_LENGTH = struct.Struct(">I")


class WireError(SidecarContractError):
    """Raised when a UDS message violates the bounded canonical wire protocol."""


def receive_message(connection: socket.socket, *, maximum: int) -> dict[str, Any] | None:
    header = _receive_exact(connection, _LENGTH.size, eof_allowed=True)
    if header is None:
        return None
    (length,) = _LENGTH.unpack(header)
    if not 1 <= length <= maximum:
        raise WireError("UDS frame length is outside the closed byte limit")
    body = _receive_exact(connection, length)
    assert body is not None
    return load_canonical_json(body, label="UDS message")


def send_message(connection: socket.socket, payload: dict[str, Any], *, maximum: int) -> None:
    body = canonical_bytes(payload)
    if not 1 <= len(body) <= maximum:
        raise WireError("UDS response length is outside the closed byte limit")
    connection.sendall(_LENGTH.pack(len(body)) + body)


def _receive_exact(
    connection: socket.socket,
    count: int,
    *,
    eof_allowed: bool = False,
) -> bytes | None:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            if eof_allowed and not chunks:
                return None
            raise WireError("UDS connection closed during a framed message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


__all__ = (
    "MAXIMUM_REQUEST_BYTES",
    "MAXIMUM_RESPONSE_BYTES",
    "WIRE_SCHEMA_VERSION",
    "WireError",
    "receive_message",
    "send_message",
)
