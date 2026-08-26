from __future__ import annotations

import hashlib
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Final

from .canonical import SidecarContractError, bytes_sha256

FUTU_HEADER: Final = struct.Struct("<1s1sI2B2I20s8s")
FUTU_HEADER_SIZE: Final = FUTU_HEADER.size
FUTU_PROTOBUF_FORMAT: Final = 0
MAXIMUM_FUTU_BODY_BYTES: Final = 16 * 1024 * 1024
MAXIMUM_DROPPED_NOTIFY_COUNT: Final = 128
MAXIMUM_DROPPED_NOTIFY_BYTES: Final = 4 * 1024 * 1024
INFRASTRUCTURE_PROTOCOL_IDS: Final = frozenset({1001, 1002, 1004})
NOTIFY_PROTOCOL_ID: Final = 1003
DEFAULT_US_QUOTE_PROTOCOL_IDS: Final = frozenset(
    {
        1002,
        3103,
        3104,
        3202,
        3227,
        3228,
        3229,
        3230,
        3232,
        3234,
        3236,
        3243,
        3244,
        3245,
        3246,
    }
)
FORBIDDEN_ACCOUNT_AND_TRADE_PROTOCOL_IDS: Final = frozenset(
    {
        1005,
        1006,
        2001,
        2005,
        2008,
        2101,
        2102,
        2111,
        2112,
        2201,
        2202,
        2205,
        2208,
        2211,
        2218,
        2221,
        2222,
        2223,
        2225,
        2226,
        2227,
    }
)


class FrameGuardError(SidecarContractError):
    """Raised when a frame escapes the closed quote-only protocol boundary."""


@dataclass(frozen=True, slots=True)
class FutuFrame:
    protocol_id: int
    protocol_format: int
    protocol_version: int
    serial_number: int
    body: bytes
    raw: bytes
    sha1_hex: str
    sha256: str

    def __post_init__(self) -> None:
        try:
            (
                magic_a,
                magic_b,
                protocol_id,
                protocol_format,
                protocol_version,
                serial_number,
                body_size,
                sha1,
                reserved,
            ) = FUTU_HEADER.unpack(self.raw[:FUTU_HEADER_SIZE])
        except struct.error as exc:
            raise FrameGuardError("Futu frame object has a truncated header") from exc
        if (
            self.raw != self.raw[:FUTU_HEADER_SIZE] + self.body
            or len(self.raw) != FUTU_HEADER_SIZE + len(self.body)
            or magic_a != b"F"
            or magic_b != b"T"
            or protocol_id != self.protocol_id
            or protocol_format != self.protocol_format
            or protocol_version != self.protocol_version
            or serial_number != self.serial_number
            or body_size != len(self.body)
            or sha1.hex() != self.sha1_hex
            or reserved != b"\0" * 8
            or bytes_sha256(self.raw) != self.sha256
            or hashlib.sha1(self.body).hexdigest() != self.sha1_hex
        ):
            raise FrameGuardError("Futu frame object does not replay its exact bytes")


@dataclass(frozen=True, slots=True)
class FrameExchange:
    sequence: int
    protocol_id: int
    serial_number: int
    request: FutuFrame
    response: FutuFrame
    completed_monotonic: float

    def __post_init__(self) -> None:
        if (
            type(self.sequence) is not int
            or self.sequence <= 0
            or type(self.request) is not FutuFrame
            or type(self.response) is not FutuFrame
            or self.protocol_id != self.request.protocol_id
            or self.protocol_id != self.response.protocol_id
            or self.serial_number != self.request.serial_number
            or self.serial_number != self.response.serial_number
            or self.completed_monotonic <= 0
        ):
            raise FrameGuardError("Futu frame exchange is internally inconsistent")

    @property
    def transcript_sha256(self) -> str:
        framed = (
            b"OWNER-RESEARCH-FUTU-FRAME-EXCHANGE-v1\0"
            + struct.pack(">I", len(self.request.raw))
            + self.request.raw
            + struct.pack(">I", len(self.response.raw))
            + self.response.raw
        )
        return bytes_sha256(framed)

    @property
    def raw_evidence(self) -> bytes:
        return (
            b"OWNER-RESEARCH-FUTU-FRAME-EXCHANGE-v1\0"
            + struct.pack(">I", len(self.request.raw))
            + self.request.raw
            + struct.pack(">I", len(self.response.raw))
            + self.response.raw
        )


@dataclass(frozen=True, slots=True)
class DroppedPushMetadata:
    protocol_id: int
    serial_number: int
    frame_sha256: str
    byte_count: int


def parse_futu_frame(header: bytes, body: bytes) -> FutuFrame:
    if len(header) != FUTU_HEADER_SIZE:
        raise FrameGuardError("Futu frame header has an invalid length")
    magic_a, magic_b, protocol_id, protocol_format, protocol_version, serial, size, sha1, _ = (
        FUTU_HEADER.unpack(header)
    )
    if magic_a != b"F" or magic_b != b"T":
        raise FrameGuardError("Futu frame magic is invalid")
    if protocol_format != FUTU_PROTOBUF_FORMAT:
        raise FrameGuardError("only Futu protobuf frames are permitted")
    if protocol_version != 0:
        raise FrameGuardError("unexpected Futu protocol version")
    if size != len(body) or size > MAXIMUM_FUTU_BODY_BYTES:
        raise FrameGuardError("Futu frame body length is invalid")
    if hashlib.sha1(body).digest() != sha1:  # noqa: S324 - vendor frame integrity field
        raise FrameGuardError("Futu frame SHA-1 integrity field does not match its body")
    if type(protocol_id) is not int or protocol_id <= 0 or serial <= 0:
        raise FrameGuardError("Futu frame protocol or serial is invalid")
    raw = header + body
    return FutuFrame(
        protocol_id=protocol_id,
        protocol_format=protocol_format,
        protocol_version=protocol_version,
        serial_number=serial,
        body=body,
        raw=raw,
        sha1_hex=sha1.hex(),
        sha256=bytes_sha256(raw),
    )


def pack_futu_frame(protocol_id: int, serial_number: int, body: bytes) -> bytes:
    """Pack a protobuf frame for the protocol-conformance fake OpenD tests."""

    if (
        type(protocol_id) is not int
        or protocol_id <= 0
        or type(serial_number) is not int
        or serial_number <= 0
        or not isinstance(body, bytes)
        or len(body) > MAXIMUM_FUTU_BODY_BYTES
    ):
        raise FrameGuardError("cannot pack an invalid Futu frame")
    header = FUTU_HEADER.pack(
        b"F",
        b"T",
        protocol_id,
        FUTU_PROTOBUF_FORMAT,
        0,
        serial_number,
        len(body),
        hashlib.sha1(body).digest(),  # noqa: S324 - exact vendor wire format
        b"\0" * 8,
    )
    return header + body


def _recv_exact(
    connection: socket.socket, count: int, *, eof_allowed: bool = False
) -> bytes | None:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            if eof_allowed and not chunks:
                return None
            raise FrameGuardError("Futu connection closed during a framed message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_futu_frame(connection: socket.socket) -> FutuFrame | None:
    header = _recv_exact(connection, FUTU_HEADER_SIZE, eof_allowed=True)
    if header is None:
        return None
    unpacked = FUTU_HEADER.unpack(header)
    body_size = unpacked[6]
    if body_size > MAXIMUM_FUTU_BODY_BYTES:
        raise FrameGuardError("Futu frame body exceeds the closed byte limit")
    body = _recv_exact(connection, body_size)
    assert body is not None
    return parse_futu_frame(header, body)


class FrameGuardProxy:
    """Loopback TCP proxy that rejects non-allowlisted protocols before OpenD.

    The official SDK connects to this proxy.  The proxy captures the exact protobuf
    frames and forwards only explicitly allowed infrastructure and quote operations to
    the real OpenD listener.  It has no API for sending arbitrary bytes.
    """

    def __init__(
        self,
        *,
        upstream_host: str,
        upstream_port: int,
        allowed_quote_protocol_ids: frozenset[int] = DEFAULT_US_QUOTE_PROTOCOL_IDS,
        connect_timeout: float = 10.0,
    ) -> None:
        if upstream_host not in {"127.0.0.1", "::1"}:
            raise FrameGuardError("OpenD must be loopback-only inside the isolated VM")
        if type(upstream_port) is not int or not 1 <= upstream_port <= 65535:
            raise FrameGuardError("OpenD port is invalid")
        if (
            not isinstance(allowed_quote_protocol_ids, frozenset)
            or 1002 not in allowed_quote_protocol_ids
            or not allowed_quote_protocol_ids.issubset(DEFAULT_US_QUOTE_PROTOCOL_IDS)
            or 3235 in allowed_quote_protocol_ids
        ):
            raise FrameGuardError("US quote allowlist includes a forbidden protocol")
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.allowed_quote_protocol_ids = allowed_quote_protocol_ids
        self.connect_timeout = connect_timeout
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._condition = threading.Condition()
        self._pending: dict[tuple[int, int], FutuFrame] = {}
        self._completed: list[FrameExchange] = []
        self._dropped_pushes: list[DroppedPushMetadata] = []
        self._connections: set[socket.socket] = set()
        self._quarantine_reason: str | None = None
        self._accepted_connection = False

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        if self._listener is None:
            raise FrameGuardError("frame guard has not started")
        return int(self._listener.getsockname()[1])

    @property
    def sequence(self) -> int:
        with self._condition:
            return len(self._completed)

    @property
    def quarantined(self) -> bool:
        with self._condition:
            return self._quarantine_reason is not None

    @property
    def quarantine_reason(self) -> str | None:
        with self._condition:
            return self._quarantine_reason

    def start(self) -> None:
        if self._listener is not None:
            raise FrameGuardError("frame guard is already running")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, 0))
        listener.listen(1)
        listener.settimeout(0.25)
        self._listener = listener
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="owner-research-futu-frame-guard",
            daemon=True,
        )
        self._accept_thread.start()

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._condition:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)

    def wait_for_exchange(
        self,
        *,
        protocol_id: int,
        after_sequence: int,
        timeout: float = 20.0,
    ) -> FrameExchange:
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                if self._quarantine_reason is not None:
                    raise FrameGuardError(
                        f"frame guard quarantined the connection: {self._quarantine_reason}"
                    )
                for exchange in self._completed:
                    if exchange.sequence > after_sequence and exchange.protocol_id == protocol_id:
                        return exchange
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FrameGuardError(
                        f"timed out waiting for protocol {protocol_id} frame evidence"
                    )
                self._condition.wait(timeout=remaining)

    def require_single_exchange(
        self,
        *,
        protocol_id: int,
        after_sequence: int,
        timeout: float = 20.0,
    ) -> FrameExchange:
        """Return the one exchange authorized by a facade call or quarantine.

        Some SDK convenience methods can issue hidden follow-up requests.  Waiting
        for the first matching response is therefore insufficient: once the SDK
        method returns, its complete transcript must contain exactly one new
        request/response pair.
        """

        exchange = self.wait_for_exchange(
            protocol_id=protocol_id,
            after_sequence=after_sequence,
            timeout=timeout,
        )
        with self._condition:
            exact = (
                len(self._completed) == after_sequence + 1
                and exchange.sequence == after_sequence + 1
                and self._completed[after_sequence] is exchange
            )
        if not exact:
            self._quarantine("sdk_facade_call_emitted_multiple_exchanges")
            raise FrameGuardError(
                "official SDK facade call emitted more than one protocol exchange"
            )
        return exchange

    def transcript(self) -> tuple[FrameExchange, ...]:
        with self._condition:
            return tuple(
                exchange
                for exchange in self._completed
                if exchange.protocol_id not in INFRASTRUCTURE_PROTOCOL_IDS
            )

    def dropped_pushes(self) -> tuple[DroppedPushMetadata, ...]:
        with self._condition:
            return tuple(self._dropped_pushes)

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                sdk_connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._condition:
                if self._accepted_connection:
                    sdk_connection.close()
                    self._quarantine("sdk_reconnect_attempt_rejected")
                    return
                self._accepted_connection = True
            try:
                self._listener.close()
            except OSError:
                pass
            try:
                upstream = socket.create_connection(
                    (self.upstream_host, self.upstream_port),
                    timeout=self.connect_timeout,
                )
                sdk_connection.settimeout(None)
                upstream.settimeout(None)
            except OSError:
                sdk_connection.close()
                self._quarantine("opend_connection_failed")
                return
            with self._condition:
                self._connections.update((sdk_connection, upstream))
            lifecycle_closed = threading.Event()
            forward = threading.Thread(
                target=self._pump_requests,
                args=(sdk_connection, upstream, lifecycle_closed),
                name="owner-research-futu-guard-requests",
                daemon=True,
            )
            backward = threading.Thread(
                target=self._pump_responses,
                args=(upstream, sdk_connection, lifecycle_closed),
                name="owner-research-futu-guard-responses",
                daemon=True,
            )
            forward.start()
            backward.start()
            return

    def _allowed(self, protocol_id: int) -> bool:
        return protocol_id in INFRASTRUCTURE_PROTOCOL_IDS or protocol_id in (
            self.allowed_quote_protocol_ids
        )

    def _pump_requests(
        self,
        source: socket.socket,
        destination: socket.socket,
        lifecycle_closed: threading.Event,
    ) -> None:
        try:
            while not self._stop.is_set():
                frame = receive_futu_frame(source)
                if frame is None:
                    with self._condition:
                        if self._pending:
                            self._quarantine_reason = (
                                self._quarantine_reason
                                or "sdk_connection_closed_with_pending_request"
                            )
                            self._condition.notify_all()
                    return
                if not self._allowed(frame.protocol_id):
                    raise FrameGuardError(f"protocol {frame.protocol_id} is forbidden before OpenD")
                key = (frame.protocol_id, frame.serial_number)
                with self._condition:
                    if self._pending:
                        raise FrameGuardError("only one Futu request may be in flight")
                    self._pending[key] = frame
                destination.sendall(frame.raw)
        except (FrameGuardError, OSError) as exc:
            if not lifecycle_closed.is_set() and not self._stop.is_set():
                self._quarantine(str(exc))
        finally:
            lifecycle_closed.set()
            self._close_pair(source, destination)

    def _pump_responses(
        self,
        source: socket.socket,
        destination: socket.socket,
        lifecycle_closed: threading.Event,
    ) -> None:
        try:
            while not self._stop.is_set():
                frame = receive_futu_frame(source)
                if frame is None:
                    with self._condition:
                        if self._pending:
                            self._quarantine_reason = (
                                self._quarantine_reason
                                or "opend_connection_closed_with_pending_request"
                            )
                            self._condition.notify_all()
                    return
                if frame.protocol_id == NOTIFY_PROTOCOL_ID:
                    _validate_notify_frame(frame)
                    with self._condition:
                        dropped_bytes = sum(item.byte_count for item in self._dropped_pushes)
                        if (
                            len(self._dropped_pushes) >= MAXIMUM_DROPPED_NOTIFY_COUNT
                            or dropped_bytes + len(frame.raw) > MAXIMUM_DROPPED_NOTIFY_BYTES
                        ):
                            raise FrameGuardError("OpenD notification budget is exhausted")
                        self._dropped_pushes.append(
                            DroppedPushMetadata(
                                protocol_id=frame.protocol_id,
                                serial_number=frame.serial_number,
                                frame_sha256=frame.sha256,
                                byte_count=len(frame.raw),
                            )
                        )
                    continue
                if not self._allowed(frame.protocol_id):
                    raise FrameGuardError(f"OpenD emitted forbidden protocol {frame.protocol_id}")
                key = (frame.protocol_id, frame.serial_number)
                with self._condition:
                    request = self._pending.pop(key, None)
                    if request is None:
                        raise FrameGuardError("OpenD response has no exact request serial")
                    exchange = FrameExchange(
                        sequence=len(self._completed) + 1,
                        protocol_id=frame.protocol_id,
                        serial_number=frame.serial_number,
                        request=request,
                        response=frame,
                        completed_monotonic=time.monotonic(),
                    )
                    self._completed.append(exchange)
                    self._condition.notify_all()
                destination.sendall(frame.raw)
        except (FrameGuardError, OSError) as exc:
            if not lifecycle_closed.is_set() and not self._stop.is_set():
                self._quarantine(str(exc))
        finally:
            lifecycle_closed.set()
            self._close_pair(source, destination)

    def _quarantine(self, reason: str) -> None:
        with self._condition:
            if self._quarantine_reason is None:
                self._quarantine_reason = reason or "frame_guard_failure"
            self._condition.notify_all()

    def _close_pair(self, *connections: socket.socket) -> None:
        with self._condition:
            for connection in connections:
                self._connections.discard(connection)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def __enter__(self) -> FrameGuardProxy:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _validate_notify_frame(frame: FutuFrame) -> None:
    try:
        from futu.common.pb import Notify_pb2  # type: ignore[import-not-found]
        from google.protobuf.message import DecodeError

        response = Notify_pb2.Response()
        response.ParseFromString(frame.body)
    except (DecodeError, ImportError) as exc:
        raise FrameGuardError("OpenD protocol 1003 notification is malformed") from exc
    if response.retType != 0 or response.errCode != 0 or not response.HasField("s2c"):
        raise FrameGuardError("OpenD protocol 1003 notification is not successful")
