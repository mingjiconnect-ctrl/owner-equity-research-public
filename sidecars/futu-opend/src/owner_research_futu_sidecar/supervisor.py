from __future__ import annotations

import hashlib
import os
import socket
import stat
import threading
from datetime import UTC, datetime
from typing import Any

from .attestation import (
    ABORT_REASON_CODES,
    MAXIMUM_CUMULATIVE_RAW_BYTES,
    MAXIMUM_DATA_OPERATIONS_PER_RUN,
    AttestationError,
    Ed25519Attestor,
    _parse_time,
    _validate_checkpoint,
    validate_supply_attestation,
)
from .canonical import (
    SidecarContractError,
    canonical_sha256,
    require_exact_members,
    require_sha256,
    signed_identity,
)
from .cas import MAXIMUM_CAS_OBJECT_BYTES
from .frame_guard import DEFAULT_US_QUOTE_PROTOCOL_IDS, INFRASTRUCTURE_PROTOCOL_IDS
from .runtime_authorization import (
    MAXIMUM_AUTHORIZATION_BYTES,
    MAXIMUM_KEYRING_BYTES,
    VerifiedRuntimeAuthorization,
    require_runtime_platform,
    verify_runtime_authorization,
)
from .wire import WIRE_SCHEMA_VERSION, receive_message, send_message

MAXIMUM_SIGNING_MESSAGE_BYTES = 20 * 1024 * 1024
_BOOT_FIELDS = {
    "schema_version",
    "receipt_id",
    "receipt_kind",
    "run_id",
    "session_id",
    "challenge_nonce",
    "boot_nonce",
    "supply_attestation",
    "runtime_authorization_fingerprint",
    "request_plan_fingerprint",
    "startup_checkpoint",
    "signer_public_key_hex",
    "issued_at",
    "signature_algorithm",
    "signer_key_id",
}
_FETCH_FIELDS = {
    "wire_schema_version",
    "command",
    "run_id",
    "request_id",
    "request_fingerprint",
    "protocol_id",
    "page_index",
    "supply_attestation",
    "pre_global_state",
    "data_response",
    "post_global_state",
    "session_id",
    "sequence",
    "boot_receipt_id",
    "signature_algorithm",
    "signer_key_id",
}
_ABORT_FIELDS = {
    "schema_version",
    "receipt_id",
    "receipt_kind",
    "run_id",
    "session_id",
    "boot_receipt_id",
    "sequence",
    "reason_code",
    "issued_at",
    "signature_algorithm",
    "signer_key_id",
}
_RUNTIME_FIELDS = {
    "schema_version",
    "receipt_id",
    "run_id",
    "runtime_authorization_fingerprint",
    "request_plan_fingerprint",
    "authorization_window_seconds",
    "policy_sha256",
    "component_lock_sha256",
    "account_scope_sha256",
    "supply_chain_fingerprint",
    "vm_image_sha256",
    "opend_version",
    "opend_server_version",
    "opend_server_build_no",
    "rootless",
    "credentials_location",
    "host_opend_port_mapped",
    "generic_raw_send_enabled",
    "logging_enabled",
    "reminder_push_enabled",
    "automatic_quote_right_takeover_enabled",
    "trade_and_account_protocols_rejected_before_opend",
    "allowed_protocol_ids",
    "checkpoints",
    "quarantined",
    "started_at",
    "ended_at",
    "issued_at",
    "expires_at",
    "signature_algorithm",
    "signer_key_id",
}
_EXECUTION_FIELDS = {
    "schema_version",
    "receipt_id",
    "receipt_kind",
    "run_id",
    "session_id",
    "boot_receipt_id",
    "supply_attestation",
    "runtime_authorization_fingerprint",
    "request_plan_fingerprint",
    "conditional_plan_disposition",
    "ordered_executions",
    "ordered_execution_root_sha256",
    "checkpoint_root_sha256",
    "started_at",
    "ended_at",
    "issued_at",
    "signature_algorithm",
    "signer_key_id",
}
_EXECUTION_RECORD_FIELDS = {
    "request_id",
    "request_fingerprint",
    "response_fingerprint",
    "protocol_id",
    "page_index",
    "serial_number",
    "request_frame_sha256",
    "response_frame_sha256",
    "frame_exchange_sha256",
    "raw_plaintext_sha256",
    "encrypted_object_sha256",
    "observation_sha256",
}
_WIRE_GLOBAL_STATE_FIELDS = {
    "operation",
    "protocol_id",
    "serial_number",
    "request_fingerprint",
    "retrieved_at",
    "ret_type",
    "err_code",
    "qot_logined",
    "trd_logined",
    "opend_server_version",
    "opend_server_build_no",
    "response_fingerprint",
}
_DATA_RESPONSE_FIELDS = {
    "serial_number",
    "retrieved_at",
    "ret_type",
    "err_code",
    "next_key",
    "terminal",
    "raw_evidence",
    "observations",
}
_RAW_EVIDENCE_FIELDS = {
    "evidence_kind",
    "raw_plaintext_sha256",
    "encrypted_object_sha256",
    "cas_locator",
    "envelope_key_id",
    "raw_byte_count",
}
_FETCH_CONTEXT_FIELDS = {
    "execution_record",
    "pre_checkpoint",
    "post_checkpoint",
    "security_code",
    "parameters_sha256",
    "page_key_sha256",
    "terminal",
    "plan_index",
}
_FETCH_AUTHORIZATION_FIELDS = {
    "protocol_version",
    "command",
    "run_id",
    "session_id",
    "boot_receipt_id",
    "sequence",
    "request_id",
    "request_fingerprint",
    "security_code",
    "protocol_id",
    "parameters_sha256",
    "page_index",
    "page_key_sha256",
    "plan_index",
}


class SupervisorError(AttestationError):
    """Raised when the isolated receipt signer violates its preopened protocol."""


class SupervisorAttestorClient:
    """Receipt attestor backed by a preopened AF_UNIX supervisor socket."""

    def __init__(
        self,
        *,
        signer_socket: socket.socket,
        expected_signer_key_id: str,
        expected_public_key_hex: str,
    ) -> None:
        if signer_socket.family != socket.AF_UNIX:
            raise SupervisorError("signer handle must be a preopened AF_UNIX socket")
        if not expected_signer_key_id:
            raise SupervisorError("expected signer key ID is invalid")
        if len(expected_public_key_hex) != 64:
            raise SupervisorError("expected Ed25519 public key is invalid")
        self._socket = signer_socket
        self._lock = threading.Lock()
        self.signer_key_id = expected_signer_key_id
        self._public_key_hex = expected_public_key_hex
        nonce = os.urandom(32).hex()
        response = self._exchange(
            {
                "protocol_version": "1.0.0",
                "command": "get_signer_identity",
                "challenge_nonce": nonce,
                "expected_signer_key_id": expected_signer_key_id,
            }
        )
        require_exact_members(
            response,
            {
                "protocol_version",
                "command",
                "challenge_nonce",
                "signer_key_id",
                "public_key_hex",
            },
            "signer identity response",
        )
        if response != {
            "protocol_version": "1.0.0",
            "command": "get_signer_identity",
            "challenge_nonce": nonce,
            "signer_key_id": expected_signer_key_id,
            "public_key_hex": expected_public_key_hex,
        }:
            raise SupervisorError("preopened signer identity differs from runtime claims")

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    def sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._sign(payload, evidence_context=None)

    def authorize_fetch(
        self,
        *,
        run_id: str,
        session_id: str,
        boot_receipt_id: str,
        sequence: int,
        request_id: str,
        request_fingerprint: str,
        security_code: str,
        protocol_id: int,
        parameters_sha256: str,
        page_index: int,
        page_key_sha256: str | None,
        plan_index: int,
    ) -> int:
        request = {
            "protocol_version": "1.0.0",
            "command": "authorize_fetch",
            "run_id": run_id,
            "session_id": session_id,
            "boot_receipt_id": boot_receipt_id,
            "sequence": sequence,
            "request_id": request_id,
            "request_fingerprint": request_fingerprint,
            "security_code": security_code,
            "protocol_id": protocol_id,
            "parameters_sha256": parameters_sha256,
            "page_index": page_index,
            "page_key_sha256": page_key_sha256,
            "plan_index": plan_index,
        }
        response = self._exchange(request)
        require_exact_members(
            response,
            _FETCH_AUTHORIZATION_FIELDS | {"authorization_ticket_sha256"},
            "fetch authorization response",
        )
        if any(response[key] != value for key, value in request.items()) or response[
            "authorization_ticket_sha256"
        ] != canonical_sha256(
            {
                "domain": "owner-research-futu-fetch-authorization-v1",
                **request,
            }
        ):
            raise SupervisorError("fetch authorization response was rebound")
        return plan_index

    def sign_fetch_envelope(
        self,
        payload: dict[str, Any],
        *,
        execution_record: dict[str, Any],
        pre_checkpoint: dict[str, Any],
        post_checkpoint: dict[str, Any],
        security_code: str,
        parameters_sha256: str,
        page_key_sha256: str | None,
        terminal: bool,
        plan_index: int,
    ) -> dict[str, Any]:
        return self._sign(
            payload,
            evidence_context={
                "execution_record": execution_record,
                "pre_checkpoint": pre_checkpoint,
                "post_checkpoint": post_checkpoint,
                "security_code": security_code,
                "parameters_sha256": parameters_sha256,
                "page_key_sha256": page_key_sha256,
                "terminal": terminal,
                "plan_index": plan_index,
            },
        )

    def _sign(
        self,
        payload: dict[str, Any],
        *,
        evidence_context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        values = dict(payload)
        if "signature_hex" in values:
            raise SupervisorError("unsigned receipt unexpectedly contains a signature")
        values["signature_algorithm"] = "ed25519"
        values["signer_key_id"] = self.signer_key_id
        request = {
            "protocol_version": "1.0.0",
            "command": "sign_receipt",
            "payload": values,
            "payload_sha256": canonical_sha256(values),
        }
        if evidence_context is not None:
            request["evidence_context"] = evidence_context
        response = self._exchange(request)
        require_exact_members(
            response,
            {
                "protocol_version",
                "command",
                "payload_sha256",
                "signature_algorithm",
                "signer_key_id",
                "signature_hex",
            },
            "signer response",
        )
        if (
            response["protocol_version"] != "1.0.0"
            or response["command"] != "sign_receipt"
            or response["payload_sha256"] != canonical_sha256(values)
            or response["signature_algorithm"] != "ed25519"
            or response["signer_key_id"] != self.signer_key_id
        ):
            raise SupervisorError("signer response rebound the receipt")
        signed = {**values, "signature_hex": response["signature_hex"]}
        Ed25519Attestor.verify(signed, public_key_hex=self.public_key_hex)
        return signed

    def close(self) -> None:
        self._socket.close()

    def _exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            send_message(
                self._socket,
                request,
                maximum=MAXIMUM_SIGNING_MESSAGE_BYTES,
            )
            response = receive_message(
                self._socket,
                maximum=MAXIMUM_SIGNING_MESSAGE_BYTES,
            )
        if response is None:
            raise SupervisorError("preopened signer closed without a response")
        return response


class _SigningPolicy:
    """One-shot signing state retained outside the Futu/data process."""

    def __init__(
        self,
        *,
        signer_key_id: str,
        public_key_hex: str,
        authorization: VerifiedRuntimeAuthorization,
    ) -> None:
        self.signer_key_id = signer_key_id
        self.public_key_hex = public_key_hex
        self.authorization = authorization
        self.request_plan = authorization.request_plan
        self.state = "new"
        self.run_id: str | None = None
        self.session_id: str | None = None
        self.boot_receipt_id: str | None = None
        self.supply_attestation: dict[str, Any] | None = None
        self.runtime_authorization_fingerprint: str | None = None
        self.checkpoints: list[dict[str, Any]] = []
        self.executions: list[dict[str, Any]] = []
        self.last_sequence = 0
        self.runtime_receipt: dict[str, Any] | None = None
        self.final_checkpoint: dict[str, Any] | None = None
        self.abort_payload_sha256: str | None = None
        self.execution_payload_sha256: str | None = None
        self.cumulative_raw_bytes = 0
        self.plan_position = 0
        self.plan_page_index = 0
        self.expected_page_key_sha256: str | None = None
        self.pending_fetch: dict[str, Any] | None = None

    def authorize(
        self,
        payload: dict[str, Any],
        *,
        evidence_context: Any | None,
    ) -> None:
        if (
            payload.get("signature_algorithm") != "ed25519"
            or payload.get("signer_key_id") != self.signer_key_id
        ):
            raise SupervisorError("receipt signer identity was rebound")
        if payload.get("receipt_kind") == "futu-sidecar-boot-attestation":
            self._authorize_boot(payload, evidence_context=evidence_context)
            return
        if payload.get("command") == "fetch_quote_data_with_global_state_guards":
            self._authorize_fetch(payload, evidence_context=evidence_context)
            return
        if payload.get("receipt_kind") == "futu-sidecar-abort":
            self._authorize_abort(payload, evidence_context=evidence_context)
            return
        if payload.get("receipt_kind") == "futu-sidecar-execution-attestation":
            self._authorize_execution(payload, evidence_context=evidence_context)
            return
        if "rootless" in payload:
            self._authorize_runtime(payload, evidence_context=evidence_context)
            return
        raise SupervisorError("receipt is outside the closed signing state machine")

    def authorize_fetch_request(self, request: Any) -> dict[str, Any]:
        values = require_exact_members(
            request, _FETCH_AUTHORIZATION_FIELDS, "supervisor fetch authorization"
        )
        if self.state != "open" or self.pending_fetch is not None:
            raise SupervisorError("fetch preauthorization is outside an open session")
        sequence = values["sequence"]
        page_index = values["page_index"]
        page_key_sha256 = values["page_key_sha256"]
        plan_index = values["plan_index"]
        if page_key_sha256 is not None:
            require_sha256(page_key_sha256, "fetch page-key SHA-256")
        if (
            values["protocol_version"] != "1.0.0"
            or values["command"] != "authorize_fetch"
            or values["run_id"] != self.run_id
            or values["session_id"] != self.session_id
            or values["boot_receipt_id"] != self.boot_receipt_id
            or type(sequence) is not int
            or sequence != self.last_sequence + 1
            or not _bounded_string(values["request_id"], maximum=512)
            or require_sha256(values["request_fingerprint"], "fetch request fingerprint")
            != values["request_fingerprint"]
            or type(plan_index) is not int
            or plan_index != self.plan_position
            or self.plan_position >= len(self.request_plan)
            or type(page_index) is not int
            or page_index != self.plan_page_index
            or len(self.executions) >= self.authorization.payload["maximum_planned_requests"]
            or len(self.executions) >= MAXIMUM_DATA_OPERATIONS_PER_RUN
            or self.cumulative_raw_bytes >= MAXIMUM_CUMULATIVE_RAW_BYTES
            or datetime.now(UTC)
            >= _parse_time(
                self.authorization.payload["expires_at"],
                "runtime authorization expires_at",
            )
        ):
            raise SupervisorError("fetch is outside the independently verified authority")
        item = self.request_plan[self.plan_position]
        if (
            values["security_code"] != item.security_code
            or values["protocol_id"] != item.protocol_id
            or require_sha256(values["parameters_sha256"], "fetch parameters SHA-256")
            != item.parameters_sha256
            or page_index >= item.maximum_pages
            or page_key_sha256 != self.expected_page_key_sha256
            or (page_index == 0 and page_key_sha256 is not None)
            or (page_index > 0 and item.pagination_mode != "internal")
        ):
            raise SupervisorError("fetch is absent, rebound, or reordered in the signed plan")
        self.pending_fetch = dict(values)
        return {
            **values,
            "authorization_ticket_sha256": canonical_sha256(
                {
                    "domain": "owner-research-futu-fetch-authorization-v1",
                    **values,
                }
            ),
        }

    def _authorize_boot(self, payload: dict[str, Any], *, evidence_context: Any | None) -> None:
        if evidence_context is not None or self.state != "new":
            raise SupervisorError("boot receipt is not the first one-shot receipt")
        require_exact_members(payload, _BOOT_FIELDS, "supervisor boot receipt")
        if (
            payload["schema_version"] != "1.0.0"
            or not _bounded_string(payload["run_id"], maximum=512)
            or not _bounded_string(payload["challenge_nonce"], minimum=16, maximum=256)
            or payload["signer_public_key_hex"] != self.public_key_hex
        ):
            raise SupervisorError("boot receipt identity is invalid")
        session_id = require_sha256(payload["session_id"], "boot session ID")
        boot_nonce = require_sha256(payload["boot_nonce"], "boot nonce")
        authorization = require_sha256(
            payload["runtime_authorization_fingerprint"],
            "runtime authorization fingerprint",
        )
        request_plan_fingerprint = require_sha256(
            payload["request_plan_fingerprint"], "request-plan fingerprint"
        )
        supply = validate_supply_attestation(payload["supply_attestation"])
        startup = _validate_checkpoint(payload["startup_checkpoint"], expected_kind="startup")
        if not startup["qot_logined"]:
            raise SupervisorError("boot checkpoint is not quote-only")
        expected_session_id = canonical_sha256(
            {
                "domain": "owner-research-futu-session-v1",
                "run_id": payload["run_id"],
                "challenge_nonce": payload["challenge_nonce"],
                "boot_nonce": boot_nonce,
                "supply_attestation": supply,
                "runtime_authorization_fingerprint": authorization,
                "request_plan_fingerprint": request_plan_fingerprint,
                "startup_checkpoint": startup,
                "signer_public_key_hex": self.public_key_hex,
            }
        )
        issued_at = _parse_time(payload["issued_at"], "boot issued_at")
        authorized_from = _parse_time(
            self.authorization.payload["valid_from"], "authorization valid_from"
        )
        authorization_expires = _parse_time(
            self.authorization.payload["expires_at"], "authorization expires_at"
        )
        if (
            payload["run_id"] != self.authorization.payload["run_id"]
            or authorization != self.authorization.fingerprint
            or request_plan_fingerprint != self.authorization.payload["request_plan_fingerprint"]
            or supply["supply_receipt_fingerprint"]
            != self.authorization.payload["supply_chain_fingerprint"]
            or supply["opend_version"] != self.authorization.payload["opend_version"]
            or not _global_state_matches_supply(startup, supply)
            or session_id != expected_session_id
            or not (
                authorized_from
                <= _parse_time(startup["observed_at"], "startup checkpoint observed_at")
                <= issued_at
                < authorization_expires
            )
            or payload["receipt_id"] != signed_identity("futu-sidecar-boot:", payload)
        ):
            raise SupervisorError("boot receipt does not replay its signed identity")
        self.run_id = payload["run_id"]
        self.session_id = session_id
        self.boot_receipt_id = payload["receipt_id"]
        self.supply_attestation = supply
        self.runtime_authorization_fingerprint = authorization
        self.checkpoints.append(startup)
        self.state = "open"

    def _authorize_fetch(self, payload: dict[str, Any], *, evidence_context: Any | None) -> None:
        if self.state != "open":
            raise SupervisorError("fetch envelope is outside an open session")
        require_exact_members(payload, _FETCH_FIELDS, "supervisor fetch envelope")
        context = require_exact_members(
            evidence_context, _FETCH_CONTEXT_FIELDS, "supervisor fetch evidence"
        )
        pending = self.pending_fetch
        if pending is None:
            raise SupervisorError("fetch envelope lacks pre-OpenD authorization")
        sequence = payload["sequence"]
        if (
            payload["wire_schema_version"] != WIRE_SCHEMA_VERSION
            or payload["run_id"] != self.run_id
            or payload["session_id"] != self.session_id
            or payload["boot_receipt_id"] != self.boot_receipt_id
            or type(sequence) is not int
            or sequence != self.last_sequence + 1
            or validate_supply_attestation(payload["supply_attestation"]) != self.supply_attestation
            or not _bounded_string(payload["request_id"], maximum=512)
            or pending["sequence"] != sequence
            or pending["request_id"] != payload["request_id"]
            or pending["request_fingerprint"] != payload["request_fingerprint"]
            or pending["protocol_id"] != payload["protocol_id"]
            or pending["page_index"] != payload["page_index"]
        ):
            raise SupervisorError("fetch envelope rebound or reordered the session")
        request_fingerprint = require_sha256(
            payload["request_fingerprint"], "fetch request fingerprint"
        )
        protocol_id = payload["protocol_id"]
        if (
            type(protocol_id) is not int
            or protocol_id not in DEFAULT_US_QUOTE_PROTOCOL_IDS
            or protocol_id in INFRASTRUCTURE_PROTOCOL_IDS
            or type(payload["page_index"]) is not int
            or payload["page_index"] < 0
        ):
            raise SupervisorError("fetch protocol or page is outside the closed scope")
        pre = _validate_wire_global_state(payload["pre_global_state"])
        post = _validate_wire_global_state(payload["post_global_state"])
        data = _validate_data_response(payload["data_response"])
        prior = self.checkpoints[-1]
        prior_time = _parse_time(prior["observed_at"], "prior checkpoint observed_at")
        pre_time = _parse_time(pre["retrieved_at"], "pre GlobalState retrieved_at")
        data_time = _parse_time(data["retrieved_at"], "data response retrieved_at")
        post_time = _parse_time(post["retrieved_at"], "post GlobalState retrieved_at")
        if not (
            prior["serial_number"]
            < pre["serial_number"]
            < data["serial_number"]
            < post["serial_number"]
            and prior_time <= pre_time <= data_time <= post_time
            and pre["qot_logined"] is True
            and post["qot_logined"] is True
            and _global_state_matches_supply(pre, self.supply_attestation)
            and _global_state_matches_supply(post, self.supply_attestation)
        ):
            raise SupervisorError("fetch evidence is not bracketed quote-only data")
        pre_checkpoint = _validate_checkpoint(
            context["pre_checkpoint"], expected_kind="pre_request"
        )
        post_checkpoint = _validate_checkpoint(
            context["post_checkpoint"], expected_kind="post_request"
        )
        if not (
            _checkpoint_matches_wire(pre_checkpoint, pre)
            and _checkpoint_matches_wire(post_checkpoint, post)
        ):
            raise SupervisorError("fetch checkpoint context differs from signed wire data")
        execution = _validate_execution_record(context["execution_record"])
        raw = data["raw_evidence"]
        expected_response_fingerprint = _host_response_fingerprint(payload, pre, post, data)
        expected_execution = {
            "request_id": payload["request_id"],
            "request_fingerprint": request_fingerprint,
            "response_fingerprint": expected_response_fingerprint,
            "protocol_id": protocol_id,
            "page_index": payload["page_index"],
            "serial_number": data["serial_number"],
            "response_frame_sha256": raw["raw_plaintext_sha256"],
            "raw_plaintext_sha256": raw["raw_plaintext_sha256"],
            "encrypted_object_sha256": raw["encrypted_object_sha256"],
            "observation_sha256": canonical_sha256(data["observations"]),
        }
        if any(execution[key] != value for key, value in expected_execution.items()):
            raise SupervisorError("fetch execution commitment differs from signed wire data")
        plan_index = context["plan_index"]
        page_key_sha256 = context["page_key_sha256"]
        parameters_sha256 = require_sha256(context["parameters_sha256"], "fetch parameters SHA-256")
        if page_key_sha256 is not None:
            require_sha256(page_key_sha256, "fetch page-key SHA-256")
        if (
            type(plan_index) is not int
            or type(context["terminal"]) is not bool
            or context["terminal"] != data["terminal"]
            or context["security_code"] != pending["security_code"]
            or parameters_sha256 != pending["parameters_sha256"]
            or page_key_sha256 != pending["page_key_sha256"]
            or plan_index != pending["plan_index"]
            or plan_index != self.plan_position
        ):
            raise SupervisorError("fetch evidence rebound its preauthorized plan item")
        item = self.request_plan[plan_index]
        next_key = data["next_key"]
        next_key_sha256 = (
            hashlib.sha256(next_key.encode("utf-8")).hexdigest()
            if isinstance(next_key, str) and next_key != "-1"
            else None
        )
        raw_byte_count = raw["raw_byte_count"]
        if (
            len(self.executions) >= self.authorization.payload["maximum_planned_requests"]
            or len(self.executions) >= MAXIMUM_DATA_OPERATIONS_PER_RUN
            or payload["page_index"] >= item.maximum_pages
            or self.cumulative_raw_bytes + raw_byte_count > MAXIMUM_CUMULATIVE_RAW_BYTES
            or (data["terminal"] and next_key_sha256 is not None)
            or (
                not data["terminal"]
                and (
                    item.pagination_mode != "internal"
                    or next_key_sha256 is None
                    or payload["page_index"] + 1 >= item.maximum_pages
                )
            )
        ):
            raise SupervisorError("fetch exceeds the closed runtime data budget")
        self.executions.append(execution)
        self.checkpoints.extend((pre_checkpoint, post_checkpoint))
        self.cumulative_raw_bytes += raw_byte_count
        self.last_sequence = sequence
        self.pending_fetch = None
        if data["terminal"]:
            self.plan_position += 1
            self.plan_page_index = 0
            self.expected_page_key_sha256 = None
        else:
            self.plan_page_index += 1
            self.expected_page_key_sha256 = next_key_sha256

    def _authorize_runtime(self, payload: dict[str, Any], *, evidence_context: Any | None) -> None:
        if (
            evidence_context is not None
            or self.state not in {"open", "finalizing"}
            or self.pending_fetch is not None
        ):
            raise SupervisorError("runtime receipt is outside finalization")
        require_exact_members(payload, _RUNTIME_FIELDS, "supervisor runtime receipt")
        payload_sha = canonical_sha256(payload)
        if self.state == "finalizing":
            if self.runtime_receipt is None or payload_sha != canonical_sha256(
                self.runtime_receipt
            ):
                raise SupervisorError("runtime receipt cannot be rebound during finalization")
            return
        assert self.supply_attestation is not None
        checkpoints = payload["checkpoints"]
        if not isinstance(checkpoints, list) or len(checkpoints) != len(self.checkpoints) + 1:
            raise SupervisorError("runtime receipt checkpoint count is invalid")
        if checkpoints[:-1] != self.checkpoints:
            raise SupervisorError("runtime receipt rewrote an observed checkpoint")
        final_checkpoint = _validate_checkpoint(checkpoints[-1], expected_kind="pre_shutdown")
        prior = self.checkpoints[-1]
        started_at = _parse_time(payload["started_at"], "runtime started_at")
        ended_at = _parse_time(payload["ended_at"], "runtime ended_at")
        issued_at = _parse_time(payload["issued_at"], "runtime issued_at")
        expires_at = _parse_time(payload["expires_at"], "runtime expires_at")
        expected_protocols = sorted(
            set(INFRASTRUCTURE_PROTOCOL_IDS) | set(DEFAULT_US_QUOTE_PROTOCOL_IDS)
        )
        authorization = self.authorization.payload
        remaining = self.request_plan[self.plan_position :]
        plan_is_finalizable = self.plan_page_index == 0 and (
            self.plan_position == len(self.request_plan)
            or (
                bool(remaining)
                and all(
                    item.activation_condition == "eligible_conclusion_only" for item in remaining
                )
            )
        )
        static_valid = (
            payload["schema_version"] == authorization["schema_version"]
            and payload["run_id"] == self.run_id
            and payload["runtime_authorization_fingerprint"]
            == self.runtime_authorization_fingerprint
            and payload["request_plan_fingerprint"] == authorization["request_plan_fingerprint"]
            and payload["authorization_window_seconds"] == 900
            and payload["policy_sha256"] == authorization["policy_sha256"]
            and payload["component_lock_sha256"] == authorization["component_lock_sha256"]
            and payload["account_scope_sha256"] == authorization["account_scope_sha256"]
            and payload["supply_chain_fingerprint"]
            == self.supply_attestation["supply_receipt_fingerprint"]
            and payload["vm_image_sha256"] == authorization["vm_image_sha256"]
            and payload["opend_version"] == self.supply_attestation["opend_version"]
            and payload["opend_server_version"]
            == self.supply_attestation["opend_server_version"]
            and payload["opend_server_build_no"]
            == self.supply_attestation["opend_server_build_no"]
            and payload["rootless"] is True
            and payload["credentials_location"] == authorization["credentials_location"]
            and payload["host_opend_port_mapped"] is False
            and payload["generic_raw_send_enabled"] is False
            and payload["logging_enabled"] is False
            and payload["reminder_push_enabled"] is False
            and payload["automatic_quote_right_takeover_enabled"] is False
            and payload["trade_and_account_protocols_rejected_before_opend"] is True
            and payload["allowed_protocol_ids"] == expected_protocols
            and payload["quarantined"] is False
            and payload["expires_at"] == authorization["expires_at"]
            and plan_is_finalizable
            and bool(self.executions)
        )
        for key in (
            "policy_sha256",
            "component_lock_sha256",
            "account_scope_sha256",
        ):
            require_sha256(payload[key], key)
        if not (
            static_valid
            and payload["started_at"] == self.checkpoints[0]["observed_at"]
            and payload["ended_at"] == final_checkpoint["observed_at"]
            and _parse_time(authorization["valid_from"], "authorization valid_from")
            <= started_at
            <= _parse_time(prior["observed_at"], "prior checkpoint observed_at")
            <= ended_at
            <= issued_at
            < expires_at
            and prior["serial_number"] < final_checkpoint["serial_number"]
            and final_checkpoint["qot_logined"] is True
            and all(
                _global_state_matches_supply(checkpoint, self.supply_attestation)
                for checkpoint in checkpoints
            )
            and payload["receipt_id"] == signed_identity("futu-runtime:", payload)
        ):
            raise SupervisorError("runtime receipt does not replay the observed session")
        self.final_checkpoint = final_checkpoint
        self.runtime_receipt = dict(payload)
        self.state = "finalizing"

    def _authorize_execution(
        self, payload: dict[str, Any], *, evidence_context: Any | None
    ) -> None:
        if evidence_context is not None or self.state not in {"finalizing", "finalized"}:
            raise SupervisorError("execution receipt is outside finalization")
        require_exact_members(payload, _EXECUTION_FIELDS, "supervisor execution receipt")
        payload_sha = canonical_sha256(payload)
        if self.state == "finalized":
            if payload_sha != self.execution_payload_sha256:
                raise SupervisorError("final execution receipt cannot be rebound")
            return
        assert self.runtime_receipt is not None
        assert self.final_checkpoint is not None
        ordered = payload["ordered_executions"]
        all_checkpoints = [*self.checkpoints, self.final_checkpoint]
        disposition = self._validate_conditional_plan_disposition(
            payload["conditional_plan_disposition"]
        )
        if (
            payload["schema_version"] != "1.0.0"
            or payload["run_id"] != self.run_id
            or payload["session_id"] != self.session_id
            or payload["boot_receipt_id"] != self.boot_receipt_id
            or validate_supply_attestation(payload["supply_attestation"]) != self.supply_attestation
            or payload["runtime_authorization_fingerprint"]
            != self.runtime_authorization_fingerprint
            or payload["request_plan_fingerprint"]
            != self.authorization.payload["request_plan_fingerprint"]
            or payload["conditional_plan_disposition"] != disposition
            or ordered != self.executions
            or payload["ordered_execution_root_sha256"] != canonical_sha256(ordered)
            or payload["checkpoint_root_sha256"] != canonical_sha256(all_checkpoints)
            or payload["started_at"] != self.runtime_receipt["started_at"]
            or payload["ended_at"] != self.runtime_receipt["ended_at"]
            or payload["issued_at"] != self.runtime_receipt["issued_at"]
            or payload["receipt_id"] != signed_identity("futu-sidecar-execution:", payload)
        ):
            raise SupervisorError("execution receipt differs from signed fetch commitments")
        self.execution_payload_sha256 = payload_sha
        self.state = "finalized"

    def _validate_conditional_plan_disposition(self, value: Any) -> dict[str, Any]:
        disposition = require_exact_members(
            value,
            {
                "status",
                "skipped_plan_indices",
                "reason_code",
                "conclusion_receipt_id",
                "conclusion_fingerprint",
            },
            "supervisor conditional request-plan disposition",
        )
        completed = {
            "status": "completed",
            "skipped_plan_indices": [],
            "reason_code": None,
            "conclusion_receipt_id": None,
            "conclusion_fingerprint": None,
        }
        if disposition["status"] == "completed":
            if (
                disposition != completed
                or self.plan_position != len(self.request_plan)
                or self.plan_page_index != 0
            ):
                raise SupervisorError("completed request-plan disposition is invalid")
            return dict(disposition)
        remaining = self.request_plan[self.plan_position :]
        conclusion_id = disposition["conclusion_receipt_id"]
        if (
            disposition["status"] != "skipped"
            or self.plan_page_index != 0
            or not remaining
            or any(item.activation_condition != "eligible_conclusion_only" for item in remaining)
            or disposition["skipped_plan_indices"] != [item.plan_index for item in remaining]
            or disposition["reason_code"] != "partial_or_contested_conclusion"
            or not _bounded_string(conclusion_id, maximum=512)
        ):
            raise SupervisorError("conditional request-plan skip is invalid")
        require_sha256(disposition["conclusion_fingerprint"], "conclusion fingerprint")
        return dict(disposition)

    def _authorize_abort(self, payload: dict[str, Any], *, evidence_context: Any | None) -> None:
        if evidence_context is not None or self.state not in {"open", "aborted"}:
            raise SupervisorError("abort receipt is outside an abortable session")
        require_exact_members(payload, _ABORT_FIELDS, "supervisor abort receipt")
        payload_sha = canonical_sha256(payload)
        if self.state == "aborted":
            if payload_sha != self.abort_payload_sha256:
                raise SupervisorError("abort receipt cannot be rebound")
            return
        issued_at = _parse_time(payload["issued_at"], "abort issued_at")
        if (
            payload["schema_version"] != "1.0.0"
            or payload["run_id"] != self.run_id
            or payload["session_id"] != self.session_id
            or payload["boot_receipt_id"] != self.boot_receipt_id
            or payload["sequence"] != self.last_sequence + 1
            or payload["reason_code"] not in ABORT_REASON_CODES
            or issued_at
            < _parse_time(self.checkpoints[-1]["observed_at"], "last checkpoint observed_at")
            or payload["receipt_id"] != signed_identity("futu-sidecar-abort:", payload)
        ):
            raise SupervisorError("abort receipt rebound the observed session")
        self.abort_payload_sha256 = payload_sha
        self.state = "aborted"


def _bounded_string(value: Any, *, minimum: int = 1, maximum: int) -> bool:
    return isinstance(value, str) and minimum <= len(value.encode("utf-8")) <= maximum


def _validate_wire_global_state(value: Any) -> dict[str, Any]:
    state = require_exact_members(value, _WIRE_GLOBAL_STATE_FIELDS, "signed wire GlobalState")
    response_fingerprint = require_sha256(
        state["response_fingerprint"], "GlobalState response fingerprint"
    )
    unsigned = dict(state)
    unsigned.pop("response_fingerprint")
    if (
        state["operation"] != "GetGlobalState"
        or state["protocol_id"] != 1002
        or type(state["serial_number"]) is not int
        or state["serial_number"] <= 0
        or state["ret_type"] != 0
        or state["err_code"] != 0
        or type(state["qot_logined"]) is not bool
        or type(state["trd_logined"]) is not bool
        or type(state["opend_server_version"]) is not int
        or state["opend_server_version"] <= 0
        or type(state["opend_server_build_no"]) is not int
        or state["opend_server_build_no"] <= 0
        or response_fingerprint != canonical_sha256(unsigned)
    ):
        raise SupervisorError("signed wire GlobalState does not replay")
    require_sha256(state["request_fingerprint"], "GlobalState request fingerprint")
    _parse_time(state["retrieved_at"], "GlobalState retrieved_at")
    return dict(state)


def _validate_data_response(value: Any) -> dict[str, Any]:
    data = require_exact_members(value, _DATA_RESPONSE_FIELDS, "signed data response")
    raw = require_exact_members(data["raw_evidence"], _RAW_EVIDENCE_FIELDS, "signed raw evidence")
    raw_sha = require_sha256(raw["raw_plaintext_sha256"], "raw plaintext SHA-256")
    encrypted_sha = require_sha256(raw["encrypted_object_sha256"], "encrypted object SHA-256")
    if (
        type(data["serial_number"]) is not int
        or data["serial_number"] <= 0
        or data["ret_type"] != 0
        or data["err_code"] != 0
        or type(data["terminal"]) is not bool
        or not isinstance(data["observations"], list)
        or not isinstance(data["next_key"], str | type(None))
        or (isinstance(data["next_key"], str) and len(data["next_key"]) > 4096)
        or raw["evidence_kind"] != "opend_protobuf_s2c_frame"
        or raw_sha == encrypted_sha
        or raw["cas_locator"] != f"cas://sha256/{encrypted_sha}"
        or not _bounded_string(raw["envelope_key_id"], maximum=128)
        or type(raw["raw_byte_count"]) is not int
        or not 1 <= raw["raw_byte_count"] <= MAXIMUM_CAS_OBJECT_BYTES
    ):
        raise SupervisorError("signed data response or CAS evidence is invalid")
    _parse_time(data["retrieved_at"], "data response retrieved_at")
    canonical_sha256(data["observations"])
    return {**data, "raw_evidence": dict(raw)}


def _checkpoint_matches_wire(checkpoint: dict[str, Any], wire_state: dict[str, Any]) -> bool:
    return (
        checkpoint["serial_number"] == wire_state["serial_number"]
        and checkpoint["observed_at"] == wire_state["retrieved_at"]
        and checkpoint["qot_logined"] == wire_state["qot_logined"]
        and checkpoint["trd_logined"] == wire_state["trd_logined"]
        and checkpoint["opend_server_version"] == wire_state["opend_server_version"]
        and checkpoint["opend_server_build_no"] == wire_state["opend_server_build_no"]
    )


def _global_state_matches_supply(
    state: dict[str, Any], supply_attestation: dict[str, Any] | None
) -> bool:
    return supply_attestation is not None and (
        state["opend_server_version"] == supply_attestation["opend_server_version"]
        and state["opend_server_build_no"]
        == supply_attestation["opend_server_build_no"]
    )


def _validate_execution_record(value: Any) -> dict[str, Any]:
    execution = require_exact_members(value, _EXECUTION_RECORD_FIELDS, "fetch execution commitment")
    if (
        not _bounded_string(execution["request_id"], maximum=512)
        or type(execution["protocol_id"]) is not int
        or execution["protocol_id"] not in DEFAULT_US_QUOTE_PROTOCOL_IDS
        or type(execution["page_index"]) is not int
        or execution["page_index"] < 0
        or type(execution["serial_number"]) is not int
        or execution["serial_number"] <= 0
    ):
        raise SupervisorError("fetch execution commitment identity is invalid")
    for key in _EXECUTION_RECORD_FIELDS - {
        "request_id",
        "protocol_id",
        "page_index",
        "serial_number",
    }:
        require_sha256(execution[key], key)
    return dict(execution)


def _host_response_fingerprint(
    payload: dict[str, Any],
    pre: dict[str, Any],
    post: dict[str, Any],
    data: dict[str, Any],
) -> str:
    raw = data["raw_evidence"]
    next_key = data["next_key"]
    assert isinstance(raw, dict)
    assert isinstance(next_key, str | type(None))
    assert isinstance(payload["supply_attestation"], dict)
    values = {
        "schema_version": "1.0.0",
        "request_id": payload["request_id"],
        "request_fingerprint": payload["request_fingerprint"],
        "run_id": payload["run_id"],
        "serial_number": data["serial_number"],
        "retrieved_at": data["retrieved_at"],
        "ret_type": data["ret_type"],
        "err_code": data["err_code"],
        "status": "completed",
        "qot_logined": True,
        "trd_logined": bool(pre["trd_logined"] or post["trd_logined"]),
        "pre_global_state_serial_number": pre["serial_number"],
        "pre_global_state_trd_logined": pre["trd_logined"],
        "pre_global_state_request_fingerprint": pre["request_fingerprint"],
        "pre_global_state_response_fingerprint": pre["response_fingerprint"],
        "post_global_state_serial_number": post["serial_number"],
        "post_global_state_trd_logined": post["trd_logined"],
        "post_global_state_request_fingerprint": post["request_fingerprint"],
        "post_global_state_response_fingerprint": post["response_fingerprint"],
        "raw_evidence_kind": raw["evidence_kind"],
        "raw_plaintext_sha256": raw["raw_plaintext_sha256"],
        "encrypted_object_sha256": raw["encrypted_object_sha256"],
        "cas_locator": raw["cas_locator"],
        "envelope_key_id": raw["envelope_key_id"],
        "raw_byte_count": raw["raw_byte_count"],
        "page_index": payload["page_index"],
        "next_key_sha256": (
            hashlib.sha256(next_key.encode("utf-8")).hexdigest()
            if next_key not in {None, "-1"}
            else None
        ),
        "terminal": data["terminal"],
        "parser_sha256": payload["supply_attestation"]["parser_sha256"],
    }
    return canonical_sha256(values)


def serve_attestor(
    *,
    signer_socket: socket.socket,
    seed_fd: int,
    authorization_fd: int,
    authorization_keyring_fd: int,
    signer_key_id: str,
) -> None:
    """Run in the supervisor process; the data process never receives the seed."""

    try:
        authorization_raw = _read_nonregular_fd(
            authorization_fd, maximum=MAXIMUM_AUTHORIZATION_BYTES
        )
        keyring_raw = _read_nonregular_fd(authorization_keyring_fd, maximum=MAXIMUM_KEYRING_BYTES)
    finally:
        os.close(authorization_fd)
        os.close(authorization_keyring_fd)
    authorization = verify_runtime_authorization(
        authorization_raw=authorization_raw,
        keyring_raw=keyring_raw,
        expected_sidecar_attestor_key_id=signer_key_id,
    )
    require_runtime_platform(authorization.payload["schema_version"])
    seed = bytearray(_read_secret_fd(seed_fd, count=32))
    try:
        attestor = Ed25519Attestor.from_private_bytes(bytes(seed), signer_key_id=signer_key_id)
    finally:
        for index in range(len(seed)):
            seed[index] = 0
        os.close(seed_fd)
    policy = _SigningPolicy(
        signer_key_id=signer_key_id,
        public_key_hex=attestor.public_key_hex,
        authorization=authorization,
    )
    with signer_socket:
        while True:
            request = receive_message(
                signer_socket,
                maximum=MAXIMUM_SIGNING_MESSAGE_BYTES,
            )
            if request is None:
                return
            command = request.get("command")
            if command == "get_signer_identity":
                require_exact_members(
                    request,
                    {
                        "protocol_version",
                        "command",
                        "challenge_nonce",
                        "expected_signer_key_id",
                    },
                    "signer identity request",
                )
                if (
                    request["protocol_version"] != "1.0.0"
                    or request["expected_signer_key_id"] != signer_key_id
                    or not isinstance(request["challenge_nonce"], str)
                    or len(request["challenge_nonce"]) != 64
                ):
                    raise SupervisorError("signer identity request is invalid")
                response = {
                    "protocol_version": "1.0.0",
                    "command": command,
                    "challenge_nonce": request["challenge_nonce"],
                    "signer_key_id": signer_key_id,
                    "public_key_hex": attestor.public_key_hex,
                }
            elif command == "authorize_fetch":
                try:
                    response = policy.authorize_fetch_request(request)
                except (SidecarContractError, TypeError, ValueError):
                    response = {
                        "protocol_version": "1.0.0",
                        "command": "authorize_fetch",
                        "status": "rejected",
                        "reason_code": "fetch_not_authorized",
                    }
            elif command == "sign_receipt":
                expected_request_fields = {
                    "protocol_version",
                    "command",
                    "payload",
                    "payload_sha256",
                }
                if "evidence_context" in request:
                    expected_request_fields.add("evidence_context")
                require_exact_members(
                    request,
                    expected_request_fields,
                    "signer receipt request",
                )
                payload = request["payload"]
                if (
                    request["protocol_version"] != "1.0.0"
                    or not isinstance(payload, dict)
                    or require_sha256(request["payload_sha256"], "payload SHA-256")
                    != canonical_sha256(payload)
                    or payload.get("signature_algorithm") != "ed25519"
                    or payload.get("signer_key_id") != signer_key_id
                ):
                    raise SupervisorError("receipt is outside the signing policy")
                try:
                    policy.authorize(
                        payload,
                        evidence_context=request.get("evidence_context"),
                    )
                    signed = attestor.sign(
                        {
                            key: value
                            for key, value in payload.items()
                            if key not in {"signature_algorithm", "signer_key_id"}
                        }
                    )
                    response = {
                        "protocol_version": "1.0.0",
                        "command": command,
                        "payload_sha256": request["payload_sha256"],
                        "signature_algorithm": "ed25519",
                        "signer_key_id": signer_key_id,
                        "signature_hex": signed["signature_hex"],
                    }
                except (SidecarContractError, TypeError, ValueError):
                    response = {
                        "protocol_version": "1.0.0",
                        "command": "sign_receipt",
                        "status": "rejected",
                        "reason_code": "signing_policy_rejected",
                    }
            else:
                raise SupervisorError("signer command is outside the closed protocol")
            send_message(
                signer_socket,
                response,
                maximum=MAXIMUM_SIGNING_MESSAGE_BYTES,
            )


def _read_secret_fd(descriptor: int, *, count: int) -> bytes:
    try:
        descriptor_stat = os.fstat(descriptor)
    except OSError as exc:
        raise SupervisorError("secret handle is unavailable") from exc
    if not _is_pipe_or_connected_local_socket(descriptor, descriptor_stat.st_mode):
        raise SupervisorError(
            "secret handle cannot be an ordinary file or device; "
            "a one-shot pipe or local socket is required"
        )
    chunks: list[bytes] = []
    remaining = count + 1
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) != count:
        raise SupervisorError("secret handle must contain exactly one fixed-size value")
    return value


def _read_nonregular_fd(descriptor: int, *, maximum: int) -> bytes:
    try:
        descriptor_stat = os.fstat(descriptor)
    except OSError as exc:
        raise SupervisorError("authorization handle is unavailable") from exc
    if not _is_pipe_or_connected_local_socket(descriptor, descriptor_stat.st_mode):
        raise SupervisorError(
            "authorization handle cannot be an ordinary file or device; "
            "a one-shot pipe or local socket is required"
        )
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if not value or len(value) > maximum:
        raise SupervisorError("authorization handle has an invalid byte count")
    return value


def _is_pipe_or_connected_local_socket(descriptor: int, mode: int) -> bool:
    if stat.S_ISFIFO(mode):
        return True
    if not stat.S_ISSOCK(mode):
        return False
    try:
        duplicate = socket.socket(fileno=os.dup(descriptor))
    except OSError:
        return False
    with duplicate:
        try:
            duplicate.getpeername()
        except OSError:
            return False
        return duplicate.family == socket.AF_UNIX


__all__ = (
    "SupervisorAttestorClient",
    "SupervisorError",
    "serve_attestor",
)
