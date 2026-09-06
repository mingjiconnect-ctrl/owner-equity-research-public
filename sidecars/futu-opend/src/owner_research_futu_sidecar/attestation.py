from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import (
    SidecarContractError,
    canonical_bytes,
    canonical_sha256,
    require_exact_members,
    require_sha256,
    signed_identity,
    utc_now,
)
from .cas import CasReceipt
from .frame_guard import (
    DEFAULT_US_QUOTE_PROTOCOL_IDS,
    INFRASTRUCTURE_PROTOCOL_IDS,
    FrameExchange,
)
from .operation_registry import (
    PINNED_SDK_SDIST_SHA256,
    PINNED_SDK_VERSION,
    PROTOBUF_DESCRIPTOR_SET_SHA256,
    SDK_ADAPTER_REGISTRY_SHA256,
)
from .runtime_authorization import (
    MAXIMUM_PAGES_PER_PROTOCOL as AUTHORIZED_MAXIMUM_PAGES,
)
from .runtime_authorization import (
    MAXIMUM_PLANNED_REQUESTS,
    RuntimeRequestPlanItem,
    runtime_credentials_location,
    validate_request_plan,
)

SUPPLY_ATTESTATION_FIELDS = {
    "supply_receipt_fingerprint",
    "provider_id",
    "provider_version",
    "opend_version",
    "opend_server_version",
    "opend_server_build_no",
    "futu_api_version",
    "futu_api_distribution_sha256",
    "sdk_operation_registry_sha256",
    "protobuf_descriptor_set_sha256",
    "protocol_descriptor_sha256",
    "facade_sha256",
    "adapter_sha256",
    "parser_sha256",
}
MAXIMUM_DATA_OPERATIONS_PER_RUN = 128
MAXIMUM_CUMULATIVE_RAW_BYTES = 256 * 1024 * 1024
MAXIMUM_PAGES_PER_PROTOCOL = 64
SESSION_REASON_CODES = frozenset(
    {
        "caller_abort",
        "frame_guard_failure",
        "protocol_violation",
        "runtime_expired",
        "runtime_budget_exceeded",
        "serial_bracketing_invalid",
        "sidecar_internal_failure",
        "startup_login_state_invalid",
        "supply_attestation_mismatch",
        "quote_login_lost",
        "pre_shutdown_login_state_invalid",
    }
)
ABORT_REASON_CODES = frozenset(
    {
        "caller_abort",
        "host_failure",
        "quote_login_lost",
        "sidecar_response_invalid",
    }
)


class AttestationError(SidecarContractError):
    """Raised when a session or signed receipt cannot be replayed."""


class ReceiptAttestor(Protocol):
    signer_key_id: str

    @property
    def public_key_hex(self) -> str: ...

    def sign(self, payload: dict[str, Any]) -> dict[str, Any]: ...

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
    ) -> int: ...

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
    ) -> dict[str, Any]: ...


def validate_supply_attestation(value: Any) -> dict[str, Any]:
    attestation = require_exact_members(value, SUPPLY_ATTESTATION_FIELDS, "supply attestation")
    for key in SUPPLY_ATTESTATION_FIELDS - {
        "opend_server_version",
        "opend_server_build_no",
    }:
        if not isinstance(attestation[key], str) or not attestation[key]:
            raise AttestationError(f"supply attestation {key} is invalid")
    if (
        type(attestation["opend_server_version"]) is not int
        or attestation["opend_server_version"] <= 0
        or type(attestation["opend_server_build_no"]) is not int
        or attestation["opend_server_build_no"] <= 0
    ):
        raise AttestationError("supply attestation OpenD server identity is invalid")
    if (
        attestation["futu_api_version"] != PINNED_SDK_VERSION
        or attestation["futu_api_distribution_sha256"] != PINNED_SDK_SDIST_SHA256
        or attestation["sdk_operation_registry_sha256"] != SDK_ADAPTER_REGISTRY_SHA256
        or attestation["protobuf_descriptor_set_sha256"]
        != PROTOBUF_DESCRIPTOR_SET_SHA256
    ):
        raise AttestationError("supply attestation differs from the pinned Futu SDK")
    for key in (
        "supply_receipt_fingerprint",
        "futu_api_distribution_sha256",
        "sdk_operation_registry_sha256",
        "protobuf_descriptor_set_sha256",
        "protocol_descriptor_sha256",
        "facade_sha256",
        "adapter_sha256",
        "parser_sha256",
    ):
        require_sha256(attestation[key], key)
    return dict(attestation)


class Ed25519Attestor:
    """Minimal signing facade; the launcher owns the private key material."""

    def __init__(self, *, private_key: Ed25519PrivateKey, signer_key_id: str) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise AttestationError("attestor requires an exact Ed25519 private key")
        if not isinstance(signer_key_id, str) or not signer_key_id:
            raise AttestationError("attestor signer key ID is invalid")
        self._private_key = private_key
        self.signer_key_id = signer_key_id

    @classmethod
    def from_private_bytes(cls, value: bytes, *, signer_key_id: str) -> Ed25519Attestor:
        if not isinstance(value, bytes) or len(value) != 32:
            raise AttestationError("Ed25519 seed must be exactly 32 bytes")
        return cls(
            private_key=Ed25519PrivateKey.from_private_bytes(value),
            signer_key_id=signer_key_id,
        )

    @property
    def public_key_hex(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = dict(payload)
        if "signature_hex" in values:
            raise AttestationError("unsigned payload unexpectedly contains a signature")
        values["signature_algorithm"] = "ed25519"
        values["signer_key_id"] = self.signer_key_id
        values["signature_hex"] = self._private_key.sign(canonical_bytes(values)).hex()
        return values

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
        """Conformance-only in-process preauthorization.

        Production uses the isolated supervisor, which independently replays the
        preopened signed runtime authorization before any OpenD data call.
        """

        del (
            run_id,
            session_id,
            boot_receipt_id,
            sequence,
            request_id,
            request_fingerprint,
            security_code,
            protocol_id,
            parameters_sha256,
            page_index,
            page_key_sha256,
        )
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
        """Sign a fetch envelope after the controller sealed its typed evidence.

        The in-process attestor exists only for conformance tests.  The production
        supervisor validates and retains all three evidence objects before signing.
        """

        del (
            execution_record,
            pre_checkpoint,
            post_checkpoint,
            security_code,
            parameters_sha256,
            page_key_sha256,
            terminal,
            plan_index,
        )
        return self.sign(payload)

    @staticmethod
    def verify(payload: dict[str, Any], *, public_key_hex: str) -> None:
        signature_hex = payload.get("signature_hex")
        if not isinstance(signature_hex, str):
            raise AttestationError("signed payload lacks a signature")
        unsigned = dict(payload)
        unsigned.pop("signature_hex")
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            key.verify(bytes.fromhex(signature_hex), canonical_bytes(unsigned))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise AttestationError("signed payload is invalid") from exc


class SessionStatus(StrEnum):
    NEW = "new"
    OPEN = "open"
    QUARANTINED = "quarantined"
    FINALIZED = "finalized"
    ABORTED = "aborted"


@dataclass(frozen=True, slots=True)
class RuntimeClaims:
    authorized_run_id: str
    runtime_authorization_fingerprint: str
    authorization_issued_at: str
    valid_from: str
    authorization_window_seconds: int
    policy_sha256: str
    component_lock_sha256: str
    account_scope_sha256: str
    supply_chain_fingerprint: str
    vm_image_sha256: str | None
    opend_version: str
    allowed_protocol_ids: tuple[int, ...]
    authorized_security_codes: tuple[str, ...]
    request_plan: tuple[RuntimeRequestPlanItem, ...]
    request_plan_fingerprint: str
    maximum_planned_requests: int
    maximum_pages_per_protocol: int
    sidecar_attestor_key_id: str
    expires_at: str

    def __post_init__(self) -> None:
        for value, label in (
            (
                self.runtime_authorization_fingerprint,
                "runtime authorization fingerprint",
            ),
            (self.policy_sha256, "policy SHA-256"),
            (self.component_lock_sha256, "component-lock SHA-256"),
            (self.account_scope_sha256, "account-scope SHA-256"),
            (self.supply_chain_fingerprint, "supply-chain fingerprint"),
            (self.request_plan_fingerprint, "request-plan fingerprint"),
        ):
            require_sha256(value, label)
        runtime_credentials_location(self.runtime_schema_version, self.vm_image_sha256)
        allowed = set(self.allowed_protocol_ids)
        closed = set(INFRASTRUCTURE_PROTOCOL_IDS | DEFAULT_US_QUOTE_PROTOCOL_IDS)
        if (
            not isinstance(self.authorized_run_id, str)
            or not self.authorized_run_id
            or not self.opend_version
            or not self.allowed_protocol_ids
            or tuple(sorted(set(self.allowed_protocol_ids))) != self.allowed_protocol_ids
            or allowed != closed
            or not isinstance(self.sidecar_attestor_key_id, str)
            or not self.sidecar_attestor_key_id
        ):
            raise AttestationError("runtime claims contain an unsafe protocol scope")
        if any(type(item) is not RuntimeRequestPlanItem for item in self.request_plan):
            raise AttestationError("runtime claims request plan has an invalid type")
        validate_request_plan(
            authorized_security_codes=self.authorized_security_codes,
            request_plan=[item.to_dict() for item in self.request_plan],
            request_plan_fingerprint=self.request_plan_fingerprint,
            maximum_planned_requests=self.maximum_planned_requests,
            maximum_pages_per_protocol=self.maximum_pages_per_protocol,
            allowed_protocol_ids=self.allowed_protocol_ids,
        )
        if (
            self.maximum_planned_requests > MAXIMUM_DATA_OPERATIONS_PER_RUN
            or self.maximum_pages_per_protocol != AUTHORIZED_MAXIMUM_PAGES
            or self.maximum_planned_requests > MAXIMUM_PLANNED_REQUESTS
        ):
            raise AttestationError("runtime claims request budget is invalid")
        issued_at = _parse_time(
            self.authorization_issued_at, "runtime authorization issued_at"
        )
        valid_from = _parse_time(self.valid_from, "runtime authorization valid_from")
        expires_at = _parse_time(self.expires_at, "runtime claims expires_at")
        if (
            self.authorization_window_seconds != 900
            or not timedelta(0) <= valid_from - issued_at <= timedelta(minutes=5)
            or not timedelta(0) < expires_at - valid_from <= timedelta(seconds=900)
        ):
            raise AttestationError("runtime authorization window is invalid")
        if expires_at <= datetime.now(UTC):
            raise AttestationError("runtime claims are expired")

    @property
    def runtime_schema_version(self) -> str:
        return "2.0.0" if self.vm_image_sha256 is None else "1.0.0"


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    request_id: str
    request_fingerprint: str
    response_fingerprint: str
    protocol_id: int
    page_index: int
    frame_exchange: FrameExchange
    cas_receipt: CasReceipt
    observation_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, str)
            or not self.request_id
            or len(self.request_id.encode("utf-8")) > 512
            or type(self.frame_exchange) is not FrameExchange
            or type(self.cas_receipt) is not CasReceipt
            or self.protocol_id != self.frame_exchange.protocol_id
            or type(self.page_index) is not int
            or self.page_index < 0
            or self.cas_receipt.raw_plaintext_sha256
            != self.frame_exchange.response.sha256
            or self.cas_receipt.raw_byte_count != len(self.frame_exchange.response.raw)
        ):
            raise AttestationError("execution record does not replay captured frame evidence")
        require_sha256(self.request_fingerprint, "host request fingerprint")
        require_sha256(self.response_fingerprint, "host response fingerprint")
        require_sha256(self.observation_sha256, "observation SHA-256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_fingerprint": self.request_fingerprint,
            "response_fingerprint": self.response_fingerprint,
            "protocol_id": self.protocol_id,
            "page_index": self.page_index,
            "serial_number": self.frame_exchange.serial_number,
            "request_frame_sha256": self.frame_exchange.request.sha256,
            "response_frame_sha256": self.frame_exchange.response.sha256,
            "frame_exchange_sha256": self.frame_exchange.transcript_sha256,
            "raw_plaintext_sha256": self.cas_receipt.raw_plaintext_sha256,
            "encrypted_object_sha256": self.cas_receipt.encrypted_object_sha256,
            "observation_sha256": self.observation_sha256,
        }


class SessionController:
    def __init__(
        self,
        *,
        attestor: ReceiptAttestor,
        supply_attestation: dict[str, Any],
        runtime_claims: RuntimeClaims,
    ) -> None:
        self.attestor = attestor
        self.supply_attestation = validate_supply_attestation(supply_attestation)
        self.runtime_claims = runtime_claims
        if (
            self.supply_attestation["supply_receipt_fingerprint"]
            != runtime_claims.supply_chain_fingerprint
            or self.supply_attestation["opend_version"] != runtime_claims.opend_version
            or attestor.signer_key_id != runtime_claims.sidecar_attestor_key_id
        ):
            raise AttestationError("runtime and supply identities differ")
        self.status = SessionStatus.NEW
        self.run_id: str | None = None
        self.session_id: str | None = None
        self.started_at: str | None = None
        self.checkpoints: list[dict[str, Any]] = []
        self.executions: list[ExecutionRecord] = []
        self._last_sequence = 0
        self._boot_receipt: dict[str, Any] | None = None
        self._abort_receipt: dict[str, Any] | None = None
        self._abort_binding: tuple[str, int, str] | None = None
        self._quarantine_reason: str | None = None
        self._cumulative_raw_bytes = 0
        self._plan_position = 0
        self._plan_page_index = 0
        self._expected_page_key_sha256: str | None = None
        self._pending_fetch: dict[str, Any] | None = None
        self._staged_fetch: dict[str, Any] | None = None
        self._fetch_contexts: list[dict[str, Any]] = []

    def open(
        self,
        *,
        run_id: str,
        challenge_nonce: str,
        expected_supply_attestation: dict[str, Any],
        expected_runtime_authorization_fingerprint: str,
        expected_authorized_security_codes: list[str],
        expected_request_plan: list[dict[str, Any]],
        expected_request_plan_fingerprint: str,
        expected_maximum_planned_requests: int,
        expected_maximum_pages_per_protocol: int,
        startup_checkpoint: dict[str, Any],
    ) -> dict[str, Any]:
        if self.status is not SessionStatus.NEW:
            raise AttestationError("sidecar session can be opened only once")
        if (
            not isinstance(run_id, str)
            or not run_id
            or run_id != self.runtime_claims.authorized_run_id
            or not isinstance(challenge_nonce, str)
            or not 16 <= len(challenge_nonce) <= 256
        ):
            raise AttestationError("session identity or challenge nonce is invalid")
        if validate_supply_attestation(expected_supply_attestation) != self.supply_attestation:
            raise AttestationError("caller supply attestation differs from the running sidecar")
        if (
            require_sha256(
                expected_runtime_authorization_fingerprint,
                "expected runtime authorization fingerprint",
            )
            != self.runtime_claims.runtime_authorization_fingerprint
        ):
            raise AttestationError("caller runtime authorization differs from the sidecar")
        expected_plan = [item.to_dict() for item in self.runtime_claims.request_plan]
        if (
            expected_authorized_security_codes
            != list(self.runtime_claims.authorized_security_codes)
            or expected_request_plan != expected_plan
            or expected_request_plan_fingerprint
            != self.runtime_claims.request_plan_fingerprint
            or expected_maximum_planned_requests
            != self.runtime_claims.maximum_planned_requests
            or expected_maximum_pages_per_protocol
            != self.runtime_claims.maximum_pages_per_protocol
        ):
            raise AttestationError("caller request plan differs from the sidecar authority")
        checkpoint = _validate_checkpoint(startup_checkpoint, expected_kind="startup")
        if not self._checkpoint_matches_pinned_opend(checkpoint):
            self.status = SessionStatus.QUARANTINED
            self._quarantine_reason = "supply_attestation_mismatch"
            raise AttestationError("startup OpenD server identity differs from pinned supply")
        observed_at = _parse_time(checkpoint["observed_at"], "startup observed_at")
        if not (
            _parse_time(self.runtime_claims.valid_from, "runtime authorization valid_from")
            <= observed_at
            < _parse_time(self.runtime_claims.expires_at, "runtime authorization expires_at")
        ):
            raise AttestationError("sidecar startup is outside the authorization window")
        if not checkpoint["qot_logined"]:
            self.status = SessionStatus.QUARANTINED
            self._quarantine_reason = "startup_login_state_invalid"
            raise AttestationError("startup GlobalState is not quote-only")
        self.run_id = run_id
        self.started_at = checkpoint["observed_at"]
        self.checkpoints.append(checkpoint)
        boot_nonce = os.urandom(32).hex()
        self.session_id = canonical_sha256(
            {
                "domain": "owner-research-futu-session-v1",
                "run_id": run_id,
                "challenge_nonce": challenge_nonce,
                "boot_nonce": boot_nonce,
                "supply_attestation": self.supply_attestation,
                "runtime_authorization_fingerprint": (
                    self.runtime_claims.runtime_authorization_fingerprint
                ),
                "request_plan_fingerprint": self.runtime_claims.request_plan_fingerprint,
                "startup_checkpoint": checkpoint,
                "signer_public_key_hex": self.attestor.public_key_hex,
            }
        )
        unsigned = {
            "schema_version": "1.0.0",
            "receipt_id": "",
            "receipt_kind": "futu-sidecar-boot-attestation",
            "run_id": run_id,
            "session_id": self.session_id,
            "challenge_nonce": challenge_nonce,
            "boot_nonce": boot_nonce,
            "supply_attestation": self.supply_attestation,
            "runtime_authorization_fingerprint": (
                self.runtime_claims.runtime_authorization_fingerprint
            ),
            "request_plan_fingerprint": self.runtime_claims.request_plan_fingerprint,
            "startup_checkpoint": checkpoint,
            "signer_public_key_hex": self.attestor.public_key_hex,
            "issued_at": utc_now(),
        }
        unsigned["signature_algorithm"] = "ed25519"
        unsigned["signer_key_id"] = self.attestor.signer_key_id
        unsigned["receipt_id"] = signed_identity("futu-sidecar-boot:", unsigned)
        unsigned.pop("signature_algorithm")
        unsigned.pop("signer_key_id")
        self._boot_receipt = self.attestor.sign(unsigned)
        self.status = SessionStatus.OPEN
        return dict(self._boot_receipt)

    def require_fetch(self, *, run_id: str, session_id: str, sequence: int) -> None:
        if self.status is not SessionStatus.OPEN:
            raise AttestationError("sidecar session is not open for data access")
        if run_id != self.run_id or session_id != self.session_id:
            raise AttestationError("fetch request rebound the sidecar session")
        if type(sequence) is not int or sequence != self._last_sequence + 1:
            raise AttestationError("fetch sequence is duplicated or reordered")

    def authorize_planned_fetch(
        self,
        *,
        sequence: int,
        request_id: str,
        request_fingerprint: str,
        security_code: str,
        protocol_id: int,
        parameters_sha256: str,
        page_index: int,
        page_key_sha256: str | None,
    ) -> int:
        if self.status is not SessionStatus.OPEN or self._pending_fetch is not None:
            raise AttestationError("sidecar cannot preauthorize another data operation")
        if (
            self.run_id is None
            or self.session_id is None
            or self._boot_receipt is None
            or type(sequence) is not int
            or sequence != self._last_sequence + 1
            or not isinstance(request_id, str)
            or not request_id
            or len(request_id.encode("utf-8")) > 512
            or self._plan_position >= len(self.runtime_claims.request_plan)
        ):
            self.quarantine("protocol_violation")
            raise AttestationError("fetch is outside the signed request plan")
        require_sha256(request_fingerprint, "host request fingerprint")
        require_sha256(parameters_sha256, "request parameters SHA-256")
        if page_key_sha256 is not None:
            require_sha256(page_key_sha256, "internal page-key SHA-256")
        item = self.runtime_claims.request_plan[self._plan_position]
        if (
            security_code != item.security_code
            or protocol_id != item.protocol_id
            or parameters_sha256 != item.parameters_sha256
            or page_index != self._plan_page_index
            or page_index >= item.maximum_pages
            or page_key_sha256 != self._expected_page_key_sha256
            or (page_index == 0 and page_key_sha256 is not None)
            or (page_index > 0 and item.pagination_mode != "internal")
            or len(self.executions) >= self.runtime_claims.maximum_planned_requests
            or len(self.executions) >= MAXIMUM_DATA_OPERATIONS_PER_RUN
            or self._cumulative_raw_bytes >= MAXIMUM_CUMULATIVE_RAW_BYTES
        ):
            self.quarantine("protocol_violation")
            raise AttestationError("fetch is absent, rebound, or reordered in the signed plan")
        authorized_index = self.attestor.authorize_fetch(
            run_id=self.run_id,
            session_id=self.session_id,
            boot_receipt_id=self._boot_receipt["receipt_id"],
            sequence=sequence,
            request_id=request_id,
            request_fingerprint=request_fingerprint,
            security_code=security_code,
            protocol_id=protocol_id,
            parameters_sha256=parameters_sha256,
            page_index=page_index,
            page_key_sha256=page_key_sha256,
            plan_index=item.plan_index,
        )
        if authorized_index != item.plan_index:
            self.quarantine("sidecar_internal_failure")
            raise AttestationError("isolated supervisor rebound the request-plan item")
        self._pending_fetch = {
            "sequence": sequence,
            "request_id": request_id,
            "request_fingerprint": request_fingerprint,
            "security_code": security_code,
            "protocol_id": protocol_id,
            "parameters_sha256": parameters_sha256,
            "page_index": page_index,
            "page_key_sha256": page_key_sha256,
            "plan_index": item.plan_index,
        }
        return item.plan_index

    def record_fetch(
        self,
        *,
        sequence: int,
        pre_checkpoint: dict[str, Any],
        post_checkpoint: dict[str, Any],
        record: ExecutionRecord,
        security_code: str,
        parameters_sha256: str,
        page_key_sha256: str | None,
        next_key_sha256: str | None,
        terminal: bool,
        plan_index: int,
    ) -> None:
        if self.status is not SessionStatus.OPEN:
            raise AttestationError("cannot record data outside an open session")
        if type(sequence) is not int or sequence != self._last_sequence + 1:
            raise AttestationError("completed fetch sequence is duplicated or reordered")
        pre = _validate_checkpoint(pre_checkpoint, expected_kind="pre_request")
        post = _validate_checkpoint(post_checkpoint, expected_kind="post_request")
        if not (
            self._checkpoint_matches_pinned_opend(pre)
            and self._checkpoint_matches_pinned_opend(post)
        ):
            self.quarantine("supply_attestation_mismatch")
            raise AttestationError("fetch OpenD server identity differs from pinned supply")
        prior = self.checkpoints[-1]
        prior_time = _parse_time(prior["observed_at"], "prior checkpoint observed_at")
        pre_time = _parse_time(pre["observed_at"], "pre-request observed_at")
        post_time = _parse_time(post["observed_at"], "post-request observed_at")
        expires_at = _parse_time(
            self.runtime_claims.expires_at, "runtime authorization expires_at"
        )
        if not (
            prior["serial_number"] < pre["serial_number"]
            and prior_time <= pre_time <= post_time < expires_at
        ):
            self.quarantine("serial_bracketing_invalid")
            raise AttestationError("fetch checkpoints are not monotonic")
        if (
            not pre["qot_logined"]
            or not post["qot_logined"]
        ):
            self.quarantine("quote_login_lost")
            raise AttestationError("fetch GlobalState is not quote-only")
        if not (
            pre["serial_number"]
            < record.frame_exchange.serial_number
            < post["serial_number"]
        ):
            self.quarantine("serial_bracketing_invalid")
            raise AttestationError("data serial is not bracketed by GlobalState")
        pending = self._pending_fetch
        if pending is None:
            self.quarantine("protocol_violation")
            raise AttestationError("completed fetch lacks supervisor preauthorization")
        expected_pending = {
            "sequence": sequence,
            "request_id": record.request_id,
            "request_fingerprint": record.request_fingerprint,
            "security_code": security_code,
            "protocol_id": record.protocol_id,
            "parameters_sha256": parameters_sha256,
            "page_index": record.page_index,
            "page_key_sha256": page_key_sha256,
            "plan_index": plan_index,
        }
        if pending != expected_pending or type(terminal) is not bool:
            self.quarantine("protocol_violation")
            raise AttestationError("completed fetch rebound its preauthorized request")
        if next_key_sha256 is not None:
            require_sha256(next_key_sha256, "next page-key SHA-256")
        item = self.runtime_claims.request_plan[plan_index]
        raw_byte_count = record.cas_receipt.raw_byte_count
        if (
            len(self.executions) >= self.runtime_claims.maximum_planned_requests
            or len(self.executions) >= MAXIMUM_DATA_OPERATIONS_PER_RUN
            or record.page_index >= item.maximum_pages
            or self._cumulative_raw_bytes + raw_byte_count
            > MAXIMUM_CUMULATIVE_RAW_BYTES
            or (
                terminal
                and next_key_sha256 is not None
            )
            or (
                not terminal
                and (
                    item.pagination_mode != "internal"
                    or next_key_sha256 is None
                    or record.page_index + 1 >= item.maximum_pages
                )
            )
        ):
            self.quarantine("runtime_budget_exceeded")
            raise AttestationError("sidecar cumulative data budget is exhausted")
        self._staged_fetch = {
            "sequence": sequence,
            "pre_checkpoint": pre,
            "post_checkpoint": post,
            "record": record,
            "context": {
                "security_code": security_code,
                "parameters_sha256": parameters_sha256,
                "page_key_sha256": page_key_sha256,
                "terminal": terminal,
                "plan_index": plan_index,
            },
            "raw_byte_count": raw_byte_count,
            "next_key_sha256": next_key_sha256,
        }

    def quarantine(self, reason: str) -> None:
        if self.status in {SessionStatus.FINALIZED, SessionStatus.ABORTED}:
            raise AttestationError("completed session cannot be quarantined")
        if reason not in SESSION_REASON_CODES:
            raise AttestationError("session quarantine reason is not a closed code")
        self.status = SessionStatus.QUARANTINED
        self._quarantine_reason = reason

    def abort(
        self,
        *,
        boot_receipt_id: str,
        sequence: int,
        reason_code: str,
    ) -> dict[str, Any]:
        binding = (boot_receipt_id, sequence, reason_code)
        if self.status is SessionStatus.ABORTED:
            if binding != self._abort_binding or self._abort_receipt is None:
                raise AttestationError("aborted session cannot be rebound")
            return dict(self._abort_receipt)
        if self.status is SessionStatus.FINALIZED:
            raise AttestationError("finalized session cannot be aborted")
        if (
            self._boot_receipt is None
            or boot_receipt_id != self._boot_receipt["receipt_id"]
            or type(sequence) is not int
            or sequence != self._last_sequence + 1
            or reason_code not in ABORT_REASON_CODES
        ):
            raise AttestationError("session abort reason is not a closed code")
        self.status = SessionStatus.ABORTED
        values: dict[str, Any] = {
            "schema_version": "1.0.0",
            "receipt_id": "",
            "receipt_kind": "futu-sidecar-abort",
            "run_id": self.run_id,
            "session_id": self.session_id,
            "boot_receipt_id": boot_receipt_id,
            "sequence": sequence,
            "reason_code": reason_code,
            "issued_at": utc_now(),
            "signature_algorithm": "ed25519",
            "signer_key_id": self.attestor.signer_key_id,
        }
        values["receipt_id"] = signed_identity("futu-sidecar-abort:", values)
        values.pop("signature_algorithm")
        values.pop("signer_key_id")
        self._abort_binding = binding
        self._abort_receipt = self.attestor.sign(values)
        return dict(self._abort_receipt)

    def finalize(
        self,
        *,
        pre_shutdown_checkpoint: dict[str, Any],
        conditional_plan_disposition: dict[str, Any],
    ) -> dict[str, Any]:
        if (
            self.status is not SessionStatus.OPEN
            or not self.executions
            or self._pending_fetch is not None
        ):
            raise AttestationError("only a non-empty open session may finalize")
        disposition = self._validate_conditional_plan_disposition(
            conditional_plan_disposition
        )
        checkpoint = _validate_checkpoint(
            pre_shutdown_checkpoint, expected_kind="pre_shutdown"
        )
        if not self._checkpoint_matches_pinned_opend(checkpoint):
            self.quarantine("supply_attestation_mismatch")
            raise AttestationError("shutdown OpenD server identity differs from pinned supply")
        if not checkpoint["qot_logined"]:
            self.quarantine("pre_shutdown_login_state_invalid")
            raise AttestationError("pre-shutdown GlobalState is not quote-only")
        ended_at = checkpoint["observed_at"]
        ended = _parse_time(ended_at, "pre-shutdown observed_at")
        prior = self.checkpoints[-1]
        if not (
            _parse_time(self.runtime_claims.valid_from, "runtime authorization valid_from")
            <= ended
            < _parse_time(self.runtime_claims.expires_at, "runtime authorization expires_at")
            and _parse_time(prior["observed_at"], "prior checkpoint observed_at") <= ended
            and prior["serial_number"] < checkpoint["serial_number"]
        ):
            self.quarantine("runtime_expired")
            raise AttestationError("sidecar finalization is outside the authorization window")
        self.checkpoints.append(checkpoint)
        issued_at = utc_now()
        runtime_receipt = self._runtime_receipt(ended_at=ended_at, issued_at=issued_at)
        execution_receipt = self._execution_receipt(
            ended_at=ended_at,
            issued_at=issued_at,
            conditional_plan_disposition=disposition,
        )
        self.status = SessionStatus.FINALIZED
        return {
            "runtime_isolation_receipt": runtime_receipt,
            "execution_attestation_receipt": execution_receipt,
        }

    def sign_fetch_envelope(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if self.status is not SessionStatus.OPEN:
            raise AttestationError("cannot sign a fetch envelope outside an open session")
        staged = self._staged_fetch
        if staged is None or self._pending_fetch is None:
            raise AttestationError("fetch evidence was not staged before signing")
        if envelope.get("sequence") != staged["sequence"]:
            raise AttestationError("fetch envelope sequence differs from sealed evidence")
        context = staged["context"]
        record = staged["record"]
        try:
            signed = self.attestor.sign_fetch_envelope(
                envelope,
                execution_record=record.to_dict(),
                pre_checkpoint=staged["pre_checkpoint"],
                post_checkpoint=staged["post_checkpoint"],
                security_code=context["security_code"],
                parameters_sha256=context["parameters_sha256"],
                page_key_sha256=context["page_key_sha256"],
                terminal=context["terminal"],
                plan_index=context["plan_index"],
            )
        except Exception:
            self.quarantine("sidecar_internal_failure")
            raise
        self.checkpoints.extend(
            (staged["pre_checkpoint"], staged["post_checkpoint"])
        )
        self.executions.append(record)
        self._fetch_contexts.append(dict(context))
        self._cumulative_raw_bytes += staged["raw_byte_count"]
        self._last_sequence = staged["sequence"]
        self._pending_fetch = None
        self._staged_fetch = None
        if context["terminal"]:
            self._plan_position += 1
            self._plan_page_index = 0
            self._expected_page_key_sha256 = None
        else:
            self._plan_page_index += 1
            self._expected_page_key_sha256 = staged["next_key_sha256"]
        return signed

    def _runtime_receipt(self, *, ended_at: str, issued_at: str) -> dict[str, Any]:
        assert self.run_id is not None
        assert self.started_at is not None
        claims = self.runtime_claims
        values: dict[str, Any] = {
            "schema_version": claims.runtime_schema_version,
            "receipt_id": "",
            "run_id": self.run_id,
            "runtime_authorization_fingerprint": (
                claims.runtime_authorization_fingerprint
            ),
            "request_plan_fingerprint": claims.request_plan_fingerprint,
            "authorization_window_seconds": claims.authorization_window_seconds,
            "policy_sha256": claims.policy_sha256,
            "component_lock_sha256": claims.component_lock_sha256,
            "account_scope_sha256": claims.account_scope_sha256,
            "supply_chain_fingerprint": claims.supply_chain_fingerprint,
            "vm_image_sha256": claims.vm_image_sha256,
            "opend_version": claims.opend_version,
            "opend_server_version": self.supply_attestation["opend_server_version"],
            "opend_server_build_no": self.supply_attestation["opend_server_build_no"],
            "rootless": True,
            "credentials_location": runtime_credentials_location(
                claims.runtime_schema_version, claims.vm_image_sha256
            ),
            "host_opend_port_mapped": False,
            "generic_raw_send_enabled": False,
            "logging_enabled": False,
            "reminder_push_enabled": False,
            "automatic_quote_right_takeover_enabled": False,
            "trade_and_account_protocols_rejected_before_opend": True,
            "allowed_protocol_ids": list(claims.allowed_protocol_ids),
            "checkpoints": list(self.checkpoints),
            "quarantined": False,
            "started_at": self.started_at,
            "ended_at": ended_at,
            "issued_at": issued_at,
            "expires_at": claims.expires_at,
            "signature_algorithm": "ed25519",
            "signer_key_id": self.attestor.signer_key_id,
        }
        values["receipt_id"] = signed_identity("futu-runtime:", values)
        values.pop("signature_algorithm")
        values.pop("signer_key_id")
        return self.attestor.sign(values)

    def _checkpoint_matches_pinned_opend(self, checkpoint: dict[str, Any]) -> bool:
        return (
            checkpoint["opend_server_version"]
            == self.supply_attestation["opend_server_version"]
            and checkpoint["opend_server_build_no"]
            == self.supply_attestation["opend_server_build_no"]
        )

    def _execution_receipt(
        self,
        *,
        ended_at: str,
        issued_at: str,
        conditional_plan_disposition: dict[str, Any],
    ) -> dict[str, Any]:
        assert self.run_id is not None
        assert self.session_id is not None
        assert self._boot_receipt is not None
        ordered = [record.to_dict() for record in self.executions]
        values: dict[str, Any] = {
            "schema_version": "1.0.0",
            "receipt_id": "",
            "receipt_kind": "futu-sidecar-execution-attestation",
            "run_id": self.run_id,
            "session_id": self.session_id,
            "boot_receipt_id": self._boot_receipt["receipt_id"],
            "supply_attestation": self.supply_attestation,
            "runtime_authorization_fingerprint": (
                self.runtime_claims.runtime_authorization_fingerprint
            ),
            "request_plan_fingerprint": self.runtime_claims.request_plan_fingerprint,
            "conditional_plan_disposition": conditional_plan_disposition,
            "ordered_executions": ordered,
            "ordered_execution_root_sha256": canonical_sha256(ordered),
            "checkpoint_root_sha256": canonical_sha256(self.checkpoints),
            "started_at": self.started_at,
            "ended_at": ended_at,
            "issued_at": issued_at,
            "signature_algorithm": "ed25519",
            "signer_key_id": self.attestor.signer_key_id,
        }
        values["receipt_id"] = signed_identity("futu-sidecar-execution:", values)
        values.pop("signature_algorithm")
        values.pop("signer_key_id")
        return self.attestor.sign(values)

    def _validate_conditional_plan_disposition(
        self, value: Any
    ) -> dict[str, Any]:
        disposition = require_exact_members(
            value,
            {
                "status",
                "skipped_plan_indices",
                "reason_code",
                "conclusion_receipt_id",
                "conclusion_fingerprint",
            },
            "conditional request-plan disposition",
        )
        if disposition["status"] == "completed":
            if (
                self._plan_position != len(self.runtime_claims.request_plan)
                or self._plan_page_index != 0
                or disposition
                != {
                    "status": "completed",
                    "skipped_plan_indices": [],
                    "reason_code": None,
                    "conclusion_receipt_id": None,
                    "conclusion_fingerprint": None,
                }
            ):
                raise AttestationError("completed plan disposition is invalid")
            return dict(disposition)
        remaining = self.runtime_claims.request_plan[self._plan_position :]
        conclusion_id = disposition["conclusion_receipt_id"]
        if (
            disposition["status"] != "skipped"
            or self._plan_page_index != 0
            or not remaining
            or any(
                item.activation_condition != "eligible_conclusion_only"
                for item in remaining
            )
            or disposition["skipped_plan_indices"]
            != [item.plan_index for item in remaining]
            or disposition["reason_code"] != "partial_or_contested_conclusion"
            or not isinstance(conclusion_id, str)
            or not 1 <= len(conclusion_id.encode("utf-8")) <= 512
        ):
            raise AttestationError("conditional plan skip disposition is invalid")
        require_sha256(
            disposition["conclusion_fingerprint"], "conclusion fingerprint"
        )
        return dict(disposition)


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise AttestationError(f"{label} must be a date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError(f"{label} must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise AttestationError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_checkpoint(value: Any, *, expected_kind: str) -> dict[str, Any]:
    checkpoint = require_exact_members(
        value,
        {
            "checkpoint",
            "protocol_id",
            "serial_number",
            "global_state_request_fingerprint",
            "global_state_response_fingerprint",
            "observed_at",
            "qot_logined",
            "trd_logined",
            "opend_server_version",
            "opend_server_build_no",
        },
        "runtime checkpoint",
    )
    if (
        checkpoint["checkpoint"] != expected_kind
        or checkpoint["protocol_id"] != 1002
        or type(checkpoint["serial_number"]) is not int
        or checkpoint["serial_number"] <= 0
        or type(checkpoint["qot_logined"]) is not bool
        or type(checkpoint["trd_logined"]) is not bool
        or type(checkpoint["opend_server_version"]) is not int
        or checkpoint["opend_server_version"] <= 0
        or type(checkpoint["opend_server_build_no"]) is not int
        or checkpoint["opend_server_build_no"] <= 0
    ):
        raise AttestationError("runtime checkpoint type or login state is invalid")
    require_sha256(
        checkpoint["global_state_request_fingerprint"],
        "GlobalState request fingerprint",
    )
    require_sha256(
        checkpoint["global_state_response_fingerprint"],
        "GlobalState response fingerprint",
    )
    _parse_time(checkpoint["observed_at"], "checkpoint observed_at")
    return dict(checkpoint)


def default_expiry(*, minutes: int = 10) -> str:
    return (datetime.now(UTC) + timedelta(minutes=minutes)).isoformat().replace(
        "+00:00", "Z"
    )


__all__ = (
    "AttestationError",
    "ABORT_REASON_CODES",
    "Ed25519Attestor",
    "ExecutionRecord",
    "MAXIMUM_CUMULATIVE_RAW_BYTES",
    "MAXIMUM_DATA_OPERATIONS_PER_RUN",
    "MAXIMUM_PAGES_PER_PROTOCOL",
    "RuntimeClaims",
    "SUPPLY_ATTESTATION_FIELDS",
    "SessionController",
    "SessionStatus",
    "default_expiry",
    "validate_supply_attestation",
)
