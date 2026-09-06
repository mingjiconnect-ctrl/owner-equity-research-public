from __future__ import annotations

import hashlib
import os
import socket
import stat
import struct
import threading
from pathlib import Path
from typing import Any

from .attestation import (
    ExecutionRecord,
    SessionController,
    SessionStatus,
    validate_supply_attestation,
)
from .canonical import (
    SidecarContractError,
    canonical_sha256,
    expected_resolved_local_path,
    require_exact_members,
    require_sha256,
    utc_now,
)
from .cas import EncryptedCas
from .frame_guard import INFRASTRUCTURE_PROTOCOL_IDS
from .opend_adapter import OfficialFutuAdapter
from .wire import (
    MAXIMUM_REQUEST_BYTES,
    MAXIMUM_RESPONSE_BYTES,
    WIRE_SCHEMA_VERSION,
    receive_message,
    send_message,
)

_OPEN_REQUEST = {
    "wire_schema_version",
    "command",
    "run_id",
    "challenge_nonce",
    "expected_supply_attestation",
    "expected_signer_key_id",
    "expected_runtime_authorization_fingerprint",
    "expected_authorized_security_codes",
    "expected_request_plan",
    "expected_request_plan_fingerprint",
    "expected_maximum_planned_requests",
    "expected_maximum_pages_per_protocol",
}
_FETCH_REQUEST = {
    "wire_schema_version",
    "command",
    "run_id",
    "request_id",
    "request_fingerprint",
    "protocol",
    "security",
    "parameters",
    "page_index",
    "page_key",
    "expected_supply_attestation",
    "global_state_guards",
    "session_id",
    "sequence",
    "boot_receipt_id",
}
_FINALIZE_REQUEST = {
    "wire_schema_version",
    "command",
    "run_id",
    "session_id",
    "boot_receipt_id",
    "sequence",
    "conditional_plan_disposition",
}
_ABORT_REQUEST = _FINALIZE_REQUEST - {"conditional_plan_disposition"} | {"reason_code"}


class FutuSidecarServerError(SidecarContractError):
    """Raised when an authenticated UDS caller violates the session protocol."""


class FutuSidecarService:
    def __init__(
        self,
        *,
        adapter: OfficialFutuAdapter,
        cas: EncryptedCas,
        controller: SessionController,
    ) -> None:
        if not isinstance(adapter, OfficialFutuAdapter):
            raise FutuSidecarServerError("service requires the exact official adapter")
        if not isinstance(cas, EncryptedCas) or not isinstance(controller, SessionController):
            raise FutuSidecarServerError("service components have invalid types")
        actual_protocols = tuple(
            sorted(
                set(INFRASTRUCTURE_PROTOCOL_IDS)
                | set(adapter.guard.allowed_quote_protocol_ids)
            )
        )
        if controller.runtime_claims.allowed_protocol_ids != actual_protocols:
            raise FutuSidecarServerError(
                "runtime claims do not bind the actual frame-guard allowlist"
            )
        self.adapter = adapter
        self.cas = cas
        self.controller = controller
        self._boot_receipt_id: str | None = None
        self._fetch_sequence = 0
        self._lock = threading.Lock()

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise FutuSidecarServerError("concurrent sidecar commands are forbidden")
        try:
            if not isinstance(request, dict):
                raise FutuSidecarServerError("sidecar request must be an object")
            if request.get("wire_schema_version") != WIRE_SCHEMA_VERSION:
                raise FutuSidecarServerError("sidecar wire schema version differs")
            command = request.get("command")
            if command == "open_quote_only_session":
                return self._open(request)
            if command == "fetch_quote_data_with_global_state_guards":
                try:
                    return self._fetch(request)
                except Exception:
                    if self.controller.status is SessionStatus.OPEN:
                        self.controller.quarantine("sidecar_internal_failure")
                    self.adapter.close()
                    raise
            if command == "finalize_quote_only_session":
                return self._finalize(request)
            if command == "abort_quote_only_session":
                return self._abort(request)
            raise FutuSidecarServerError("sidecar command is outside the closed protocol")
        finally:
            self._lock.release()

    def _open(self, request: dict[str, Any]) -> dict[str, Any]:
        require_exact_members(request, _OPEN_REQUEST, "open-session request")
        if request["expected_signer_key_id"] != self.controller.attestor.signer_key_id:
            raise FutuSidecarServerError("open request expected another signer key")
        startup = self.adapter.global_state()
        checkpoint = _checkpoint(
            "startup",
            startup.exchange,
            startup.qot_logined,
            startup.trd_logined,
            opend_server_version=startup.server_version,
            opend_server_build_no=startup.server_build_no,
        )
        boot = self.controller.open(
            run_id=request["run_id"],
            challenge_nonce=request["challenge_nonce"],
            expected_supply_attestation=request["expected_supply_attestation"],
            expected_runtime_authorization_fingerprint=request[
                "expected_runtime_authorization_fingerprint"
            ],
            expected_authorized_security_codes=request[
                "expected_authorized_security_codes"
            ],
            expected_request_plan=request["expected_request_plan"],
            expected_request_plan_fingerprint=request[
                "expected_request_plan_fingerprint"
            ],
            expected_maximum_planned_requests=request[
                "expected_maximum_planned_requests"
            ],
            expected_maximum_pages_per_protocol=request[
                "expected_maximum_pages_per_protocol"
            ],
            startup_checkpoint=checkpoint,
        )
        self._boot_receipt_id = boot["receipt_id"]
        return {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "open_quote_only_session",
            "run_id": request["run_id"],
            "session_id": self.controller.session_id,
            "boot_attestation": boot,
        }

    def _fetch(self, request: dict[str, Any]) -> dict[str, Any]:
        require_exact_members(request, _FETCH_REQUEST, "fetch request")
        sequence = request["sequence"]
        self._require_session_bindings(request, sequence=sequence)
        if validate_supply_attestation(request["expected_supply_attestation"]) != (
            self.controller.supply_attestation
        ):
            self.controller.quarantine("supply_attestation_mismatch")
            raise FutuSidecarServerError("fetch supply attestation differs")
        protocol = require_exact_members(request["protocol"], {"id", "name"}, "protocol")
        security = require_exact_members(
            request["security"], {"market", "code", "security_id"}, "security"
        )
        guards = require_exact_members(
            request["global_state_guards"],
            {
                "protocol_id",
                "required_pre_request_fingerprint",
                "required_post_request_fingerprint",
                "qot_logined",
                "trd_logined",
            },
            "GlobalState guards",
        )
        if (
            security["market"] != "US"
            or guards["protocol_id"] != 1002
            or guards["qot_logined"] is not True
            or guards["trd_logined"] is not False
        ):
            raise FutuSidecarServerError("fetch request is not US quote-only")
        self._validate_host_global_fingerprints(request, guards)
        protocol_id = protocol["id"]
        if type(protocol_id) is not int or protocol_id == 1002:
            raise FutuSidecarServerError("caller data protocol is invalid")
        if type(request["page_index"]) is not int or request["page_index"] < 0:
            raise FutuSidecarServerError("page index is invalid")
        request_fingerprint = require_sha256(
            request["request_fingerprint"], "host request fingerprint"
        )
        if not isinstance(request["request_id"], str) or not request["request_id"]:
            raise FutuSidecarServerError("host request ID is invalid")
        if not isinstance(request["parameters"], dict):
            raise FutuSidecarServerError("host request parameters must be an object")
        parameters_sha256 = canonical_sha256(request["parameters"])
        page_key_sha256 = _page_key_sha256(request["page_key"])
        plan_index = self.controller.authorize_planned_fetch(
            sequence=sequence,
            request_id=request["request_id"],
            request_fingerprint=request_fingerprint,
            security_code=security["code"],
            protocol_id=protocol_id,
            parameters_sha256=parameters_sha256,
            page_index=request["page_index"],
            page_key_sha256=page_key_sha256,
        )

        pre = self.adapter.global_state()
        pre_time = utc_now()
        if not pre.qot_logined or pre.trd_logined:
            self.controller.quarantine("trade_or_quote_login_transition")
            raise FutuSidecarServerError("pre-request GlobalState is not quote-only")
        data_call = self.adapter.fetch(
            protocol_id=protocol_id,
            code=security["code"],
            parameters=request["parameters"],
            page_key=request["page_key"],
        )
        data_time = utc_now()
        post = self.adapter.global_state()
        post_time = utc_now()
        if not post.qot_logined or post.trd_logined:
            self.controller.quarantine("trade_or_quote_login_transition")
            raise FutuSidecarServerError("post-request GlobalState is not quote-only")
        parsed = data_call.parsed
        if not (
            pre.exchange.serial_number
            < parsed.exchange.serial_number
            < post.exchange.serial_number
        ):
            self.controller.quarantine("serial_bracketing_invalid")
            raise FutuSidecarServerError("GlobalState serials do not bracket data")

        cas_receipt = self.cas.store(parsed.exchange.response.raw)
        pre_wire = _wire_global_state(
            phase_fingerprint=guards["required_pre_request_fingerprint"],
            exchange=pre.exchange,
            retrieved_at=pre_time,
            qot_logined=pre.qot_logined,
            trd_logined=pre.trd_logined,
            opend_server_version=pre.server_version,
            opend_server_build_no=pre.server_build_no,
        )
        post_wire = _wire_global_state(
            phase_fingerprint=guards["required_post_request_fingerprint"],
            exchange=post.exchange,
            retrieved_at=post_time,
            qot_logined=post.qot_logined,
            trd_logined=post.trd_logined,
            opend_server_version=post.server_version,
            opend_server_build_no=post.server_build_no,
        )
        raw = {
            "evidence_kind": "opend_protobuf_s2c_frame",
            **cas_receipt.to_dict(),
        }
        data_response = {
            "serial_number": parsed.exchange.serial_number,
            "retrieved_at": data_time,
            "ret_type": parsed.ret_type,
            "err_code": parsed.err_code,
            "next_key": parsed.next_key,
            "terminal": parsed.terminal,
            "raw_evidence": raw,
            "observations": list(parsed.observations),
        }
        response_fingerprint = _host_response_fingerprint(
            request=request,
            pre=pre_wire,
            post=post_wire,
            data=data_response,
            parser_sha256=self.controller.supply_attestation["parser_sha256"],
        )
        observation_sha256 = canonical_sha256(list(parsed.observations))
        record = ExecutionRecord(
            request_id=request["request_id"],
            request_fingerprint=request_fingerprint,
            response_fingerprint=response_fingerprint,
            protocol_id=protocol_id,
            page_index=request["page_index"],
            frame_exchange=parsed.exchange,
            cas_receipt=cas_receipt,
            observation_sha256=observation_sha256,
        )
        self.controller.record_fetch(
            sequence=sequence,
            pre_checkpoint=_checkpoint(
                "pre_request",
                pre.exchange,
                pre.qot_logined,
                pre.trd_logined,
                opend_server_version=pre.server_version,
                opend_server_build_no=pre.server_build_no,
                observed_at=pre_time,
            ),
            post_checkpoint=_checkpoint(
                "post_request",
                post.exchange,
                post.qot_logined,
                post.trd_logined,
                opend_server_version=post.server_version,
                opend_server_build_no=post.server_build_no,
                observed_at=post_time,
            ),
            record=record,
            security_code=security["code"],
            parameters_sha256=parameters_sha256,
            page_key_sha256=page_key_sha256,
            next_key_sha256=_page_key_sha256(parsed.next_key),
            terminal=parsed.terminal,
            plan_index=plan_index,
        )
        envelope = {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "fetch_quote_data_with_global_state_guards",
            "run_id": request["run_id"],
            "request_id": request["request_id"],
            "request_fingerprint": request_fingerprint,
            "protocol_id": protocol_id,
            "page_index": request["page_index"],
            "supply_attestation": self.controller.supply_attestation,
            "pre_global_state": pre_wire,
            "data_response": data_response,
            "post_global_state": post_wire,
            "session_id": self.controller.session_id,
            "sequence": sequence,
            "boot_receipt_id": self._boot_receipt_id,
        }
        self._fetch_sequence = sequence
        return self.controller.sign_fetch_envelope(envelope)

    def _finalize(self, request: dict[str, Any]) -> dict[str, Any]:
        require_exact_members(request, _FINALIZE_REQUEST, "finalize request")
        self._require_session_bindings(
            request, sequence=request["sequence"], mode="finalize"
        )
        final_state = self.adapter.global_state()
        checkpoint = _checkpoint(
            "pre_shutdown",
            final_state.exchange,
            final_state.qot_logined,
            final_state.trd_logined,
            opend_server_version=final_state.server_version,
            opend_server_build_no=final_state.server_build_no,
        )
        receipts = self.controller.finalize(
            pre_shutdown_checkpoint=checkpoint,
            conditional_plan_disposition=request["conditional_plan_disposition"],
        )
        self.adapter.close()
        return {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "finalize_quote_only_session",
            "run_id": request["run_id"],
            "session_id": request["session_id"],
            "sequence": request["sequence"],
            **receipts,
        }

    def _abort(self, request: dict[str, Any]) -> dict[str, Any]:
        require_exact_members(request, _ABORT_REQUEST, "abort request")
        self._require_session_bindings(request, sequence=request["sequence"], mode="abort")
        self.adapter.close()
        receipt = self.controller.abort(
            boot_receipt_id=request["boot_receipt_id"],
            sequence=request["sequence"],
            reason_code=request["reason_code"],
        )
        return {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "abort_quote_only_session",
            "run_id": request["run_id"],
            "session_id": request["session_id"],
            "sequence": request["sequence"],
            "abort_attestation": receipt,
        }

    def _require_session_bindings(
        self,
        request: dict[str, Any],
        *,
        sequence: Any,
        mode: str = "fetch",
    ) -> None:
        if self._boot_receipt_id is None or self.controller.session_id is None:
            raise FutuSidecarServerError("sidecar session has not been opened")
        expected_sequence = self._fetch_sequence + 1
        if (
            request["run_id"] != self.controller.run_id
            or request["session_id"] != self.controller.session_id
            or request["boot_receipt_id"] != self._boot_receipt_id
            or type(sequence) is not int
            or sequence != expected_sequence
        ):
            raise FutuSidecarServerError("command rebound or reordered the session")
        if mode == "finalize":
            if self.controller.status is not SessionStatus.OPEN:
                raise FutuSidecarServerError("session cannot finalize in its current state")
        elif mode == "abort":
            if self.controller.status not in {
                SessionStatus.OPEN,
                SessionStatus.QUARANTINED,
                SessionStatus.ABORTED,
            }:
                raise FutuSidecarServerError("session cannot abort in its current state")
        elif mode == "fetch":
            self.controller.require_fetch(
                run_id=request["run_id"],
                session_id=request["session_id"],
                sequence=sequence,
            )
        else:  # pragma: no cover - internal closed dispatch
            raise AssertionError("unknown session binding mode")

    @staticmethod
    def _validate_host_global_fingerprints(
        request: dict[str, Any], guards: dict[str, Any]
    ) -> None:
        for phase, member in (
            ("pre", "required_pre_request_fingerprint"),
            ("post", "required_post_request_fingerprint"),
        ):
            expected = canonical_sha256(
                {
                    "schema_version": WIRE_SCHEMA_VERSION,
                    "operation": "GetGlobalState",
                    "protocol_id": 1002,
                    "run_id": request["run_id"],
                    "bound_data_request_fingerprint": request["request_fingerprint"],
                    "phase": phase,
                }
            )
            if guards[member] != expected:
                raise FutuSidecarServerError("GlobalState logical fingerprint is rebound")


class FutuSidecarServer:
    def __init__(
        self,
        *,
        socket_path: Path,
        service: FutuSidecarService,
        expected_peer_uid: int,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.service = service
        self.expected_peer_uid = expected_peer_uid
        self._listener: socket.socket | None = None
        self._endpoint_identity: tuple[int, int, int, int, int] | None = None
        self._parent_identity: tuple[int, int, int, int] | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._listener is not None:
            raise FutuSidecarServerError("UDS server is already running")
        parent = self.socket_path.parent
        parent_stat = parent.lstat()
        if (
            not self.socket_path.is_absolute()
            or parent.resolve(strict=True) != expected_resolved_local_path(parent)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            raise FutuSidecarServerError("UDS parent must be private and owner-controlled")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise FutuSidecarServerError("UDS path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        endpoint_stat = self.socket_path.lstat()
        if (
            not stat.S_ISSOCK(endpoint_stat.st_mode)
            or endpoint_stat.st_uid != os.getuid()
            or stat.S_IMODE(endpoint_stat.st_mode) != 0o600
            or endpoint_stat.st_nlink != 1
        ):
            listener.close()
            raise FutuSidecarServerError("bound UDS endpoint identity is invalid")
        listener.listen(4)
        listener.settimeout(0.25)
        self._parent_identity = (
            parent_stat.st_dev,
            parent_stat.st_ino,
            parent_stat.st_uid,
            stat.S_IMODE(parent_stat.st_mode),
        )
        self._endpoint_identity = (
            endpoint_stat.st_dev,
            endpoint_stat.st_ino,
            endpoint_stat.st_uid,
            stat.S_IMODE(endpoint_stat.st_mode),
            endpoint_stat.st_nlink,
        )
        self._listener = listener

    def serve_forever(self) -> None:
        if self._listener is None:
            self.start()
        assert self._listener is not None
        listener = self._listener
        while not self._stop.is_set():
            try:
                self._verify_endpoint()
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                self._verify_endpoint()
                connection.settimeout(30)
                if _peer_uid(connection) != self.expected_peer_uid:
                    continue
                try:
                    request = receive_message(connection, maximum=MAXIMUM_REQUEST_BYTES)
                    if request is None:
                        continue
                    response = self.service.handle(request)
                    send_message(connection, response, maximum=MAXIMUM_RESPONSE_BYTES)
                    if self.service.controller.status in {
                        SessionStatus.FINALIZED,
                        SessionStatus.ABORTED,
                    }:
                        self._stop.set()
                except (SidecarContractError, OSError):
                    continue

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            listener.close()
        try:
            self._verify_endpoint()
        except OSError:
            pass
        except FutuSidecarServerError:
            return
        try:
            self.socket_path.unlink()
        except OSError:
            pass

    def _verify_endpoint(self) -> None:
        if self._endpoint_identity is None or self._parent_identity is None:
            raise FutuSidecarServerError("UDS endpoint was not initialized")
        try:
            parent_stat = self.socket_path.parent.lstat()
            endpoint_stat = self.socket_path.lstat()
        except OSError as exc:
            raise FutuSidecarServerError("UDS endpoint identity is unavailable") from exc
        parent_identity = (
            parent_stat.st_dev,
            parent_stat.st_ino,
            parent_stat.st_uid,
            stat.S_IMODE(parent_stat.st_mode),
        )
        endpoint_identity = (
            endpoint_stat.st_dev,
            endpoint_stat.st_ino,
            endpoint_stat.st_uid,
            stat.S_IMODE(endpoint_stat.st_mode),
            endpoint_stat.st_nlink,
        )
        if (
            parent_identity != self._parent_identity
            or endpoint_identity != self._endpoint_identity
            or not stat.S_ISDIR(parent_stat.st_mode)
            or not stat.S_ISSOCK(endpoint_stat.st_mode)
        ):
            raise FutuSidecarServerError("UDS endpoint was replaced or its mode drifted")


def _peer_uid(connection: socket.socket) -> int:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        uid, _ = getpeereid()
        return int(uid)
    if hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, uid, _ = struct.unpack("3i", credentials)
        return int(uid)
    if hasattr(socket, "LOCAL_PEERCRED"):
        credentials = connection.getsockopt(0, socket.LOCAL_PEERCRED, 8)
        version, uid = struct.unpack("@II", credentials)
        if version != 0:
            raise FutuSidecarServerError("platform returned an unknown peer credential version")
        return int(uid)
    raise FutuSidecarServerError("platform cannot prove UDS peer credentials")


def _page_key_sha256(value: Any) -> str | None:
    if value is None or value == "-1":
        return None
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 4096:
        raise FutuSidecarServerError("internal page key is invalid")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _checkpoint(
    kind: str,
    exchange: Any,
    qot_logined: bool,
    trd_logined: bool,
    *,
    opend_server_version: int,
    opend_server_build_no: int,
    observed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "checkpoint": kind,
        "protocol_id": 1002,
        "serial_number": exchange.serial_number,
        "global_state_request_fingerprint": exchange.request.sha256,
        "global_state_response_fingerprint": exchange.response.sha256,
        "observed_at": observed_at or utc_now(),
        "qot_logined": qot_logined,
        "trd_logined": trd_logined,
        "opend_server_version": opend_server_version,
        "opend_server_build_no": opend_server_build_no,
    }


def _wire_global_state(
    *,
    phase_fingerprint: str,
    exchange: Any,
    retrieved_at: str,
    qot_logined: bool,
    trd_logined: bool,
    opend_server_version: int,
    opend_server_build_no: int,
) -> dict[str, Any]:
    values = {
        "operation": "GetGlobalState",
        "protocol_id": 1002,
        "serial_number": exchange.serial_number,
        "request_fingerprint": phase_fingerprint,
        "retrieved_at": retrieved_at,
        "ret_type": 0,
        "err_code": 0,
        "qot_logined": qot_logined,
        "trd_logined": trd_logined,
        "opend_server_version": opend_server_version,
        "opend_server_build_no": opend_server_build_no,
    }
    return {**values, "response_fingerprint": canonical_sha256(values)}


def _host_response_fingerprint(
    *,
    request: dict[str, Any],
    pre: dict[str, Any],
    post: dict[str, Any],
    data: dict[str, Any],
    parser_sha256: str,
) -> str:
    raw = data["raw_evidence"]
    next_key = data["next_key"]
    values = {
        "schema_version": "1.0.0",
        "request_id": request["request_id"],
        "request_fingerprint": request["request_fingerprint"],
        "run_id": request["run_id"],
        "serial_number": data["serial_number"],
        "retrieved_at": data["retrieved_at"],
        "ret_type": data["ret_type"],
        "err_code": data["err_code"],
        "status": "completed",
        "qot_logined": True,
        "trd_logined": False,
        "pre_global_state_serial_number": pre["serial_number"],
        "pre_global_state_request_fingerprint": pre["request_fingerprint"],
        "pre_global_state_response_fingerprint": pre["response_fingerprint"],
        "post_global_state_serial_number": post["serial_number"],
        "post_global_state_request_fingerprint": post["request_fingerprint"],
        "post_global_state_response_fingerprint": post["response_fingerprint"],
        "raw_evidence_kind": raw["evidence_kind"],
        "raw_plaintext_sha256": raw["raw_plaintext_sha256"],
        "encrypted_object_sha256": raw["encrypted_object_sha256"],
        "cas_locator": raw["cas_locator"],
        "envelope_key_id": raw["envelope_key_id"],
        "raw_byte_count": raw["raw_byte_count"],
        "page_index": request["page_index"],
        "next_key_sha256": (
            hashlib.sha256(next_key.encode("utf-8")).hexdigest()
            if next_key not in {None, "-1"}
            else None
        ),
        "terminal": data["terminal"],
        "parser_sha256": parser_sha256,
    }
    return canonical_sha256(values)


__all__ = ("FutuSidecarServer", "FutuSidecarServerError", "FutuSidecarService")
