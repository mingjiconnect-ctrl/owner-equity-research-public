from __future__ import annotations

import argparse
import os
import socket
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .attestation import RuntimeClaims, SessionController
from .canonical import (
    SidecarContractError,
    canonical_json,
    load_canonical_json,
    require_exact_members,
)
from .cas import EncryptedCas
from .frame_guard import FrameGuardProxy
from .opend_adapter import OfficialFutuAdapter
from .operation_registry import verify_installed_sdk
from .runtime_authorization import RuntimeRequestPlanItem
from .sdk_logging import FutuSdkLogBoundary
from .server import FutuSidecarServer, FutuSidecarService
from .supervisor import SupervisorAttestorClient
from .supply_identity import (
    verify_local_supply_attestation,
    verify_local_supply_identity,
)

MAXIMUM_CONFIG_BYTES = 1024 * 1024
_CONFIG_FIELDS = {
    "schema_version",
    "socket_path",
    "cas_root",
    "cas_key_id",
    "private_home",
    "opend_host",
    "opend_port",
    "expected_peer_uid",
    "supply_attestation",
    "runtime_claims",
    "signer",
}
_RUNTIME_CLAIM_FIELDS = {
    "authorized_run_id",
    "runtime_authorization_fingerprint",
    "authorization_issued_at",
    "valid_from",
    "authorization_window_seconds",
    "policy_sha256",
    "component_lock_sha256",
    "account_scope_sha256",
    "supply_chain_fingerprint",
    "vm_image_sha256",
    "opend_version",
    "allowed_protocol_ids",
    "authorized_security_codes",
    "request_plan",
    "request_plan_fingerprint",
    "maximum_planned_requests",
    "maximum_pages_per_protocol",
    "sidecar_attestor_key_id",
    "expires_at",
}


class SidecarCliError(SidecarContractError):
    """Raised when the rootless preopened launch contract is invalid."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="owner-research-futu-sidecar")
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify = subcommands.add_parser(
        "verify-sdk", help="verify the complete pinned futu-api runtime tree"
    )
    verify.add_argument("--private-home", required=True)
    serve = subcommands.add_parser(
        "serve", help="serve one quote-only attested session using preopened handles"
    )
    serve.add_argument("--config-fd", type=int, required=True)
    serve.add_argument("--cas-key-fd", type=int, required=True)
    serve.add_argument("--signer-fd", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    sys.dont_write_bytecode = True
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "verify-sdk":
            boundary = FutuSdkLogBoundary(private_home=Path(arguments.private_home))
            boundary.activate_environment()
            result = verify_installed_sdk()
            local_supply = verify_local_supply_identity()
            from futu.common import ft_logger  # type: ignore[import-not-found]

            boundary.silence(ft_logger)
            print(canonical_json({**result, "local_sidecar_supply": local_supply.to_dict()}))
            boundary.assert_quiescent()
            return 0
        if os.geteuid() == 0:
            raise SidecarCliError("Futu sidecar refuses to run as root")
        return _serve(
            config_fd=arguments.config_fd,
            cas_key_fd=arguments.cas_key_fd,
            signer_fd=arguments.signer_fd,
        )
    except (OSError, SidecarContractError) as exc:
        print(f"owner-research-futu-sidecar: {exc}", file=sys.stderr)
        return 2


def _serve(*, config_fd: int, cas_key_fd: int, signer_fd: int) -> int:
    config = _load_config(config_fd)
    local_supply_attestation = verify_local_supply_attestation(config["supply_attestation"])
    signer_values = require_exact_members(
        config["signer"], {"key_id", "public_key_hex"}, "signer configuration"
    )
    signer_socket = socket.socket(fileno=signer_fd)
    attestor = SupervisorAttestorClient(
        signer_socket=signer_socket,
        expected_signer_key_id=signer_values["key_id"],
        expected_public_key_hex=signer_values["public_key_hex"],
    )
    cas_key = bytearray(_read_nonregular_fd(cas_key_fd, maximum=32, exact=32))
    try:
        cas = EncryptedCas(
            root=Path(config["cas_root"]),
            key=bytes(cas_key),
            key_id=config["cas_key_id"],
        )
    finally:
        for index in range(len(cas_key)):
            cas_key[index] = 0
        os.close(cas_key_fd)
    claims_payload = require_exact_members(
        config["runtime_claims"], _RUNTIME_CLAIM_FIELDS, "runtime claims"
    )
    allowed = claims_payload["allowed_protocol_ids"]
    codes = claims_payload["authorized_security_codes"]
    plan = claims_payload["request_plan"]
    if not isinstance(allowed, list) or not isinstance(codes, list) or not isinstance(plan, list):
        raise SidecarCliError("runtime protocol, security, and plan claims must be lists")
    claims = RuntimeClaims(
        **{
            **claims_payload,
            "allowed_protocol_ids": tuple(allowed),
            "authorized_security_codes": tuple(codes),
            "request_plan": tuple(RuntimeRequestPlanItem.from_value(item) for item in plan),
        }
    )
    guard = FrameGuardProxy(
        upstream_host=config["opend_host"],
        upstream_port=config["opend_port"],
    )
    guard.start()
    adapter: OfficialFutuAdapter | None = None
    server: FutuSidecarServer | None = None
    try:
        adapter = OfficialFutuAdapter(
            guard=guard,
            private_home=Path(config["private_home"]),
        )
        controller = SessionController(
            attestor=attestor,
            supply_attestation=local_supply_attestation,
            runtime_claims=claims,
        )
        service = FutuSidecarService(adapter=adapter, cas=cas, controller=controller)
        server = FutuSidecarServer(
            socket_path=Path(config["socket_path"]),
            service=service,
            expected_peer_uid=config["expected_peer_uid"],
        )
        server.serve_forever()
        return 0
    finally:
        if server is not None:
            server.close()
        if adapter is not None:
            adapter.close()
        else:
            guard.close()
        attestor.close()


def _load_config(descriptor: int) -> dict[str, Any]:
    raw = _read_nonregular_fd(descriptor, maximum=MAXIMUM_CONFIG_BYTES)
    os.close(descriptor)
    config = require_exact_members(
        load_canonical_json(raw, label="sidecar launch configuration"),
        _CONFIG_FIELDS,
        "sidecar launch configuration",
    )
    if (
        config["schema_version"] != "1.0.0"
        or config["opend_host"] not in {"127.0.0.1", "::1"}
        or type(config["opend_port"]) is not int
        or not 1 <= config["opend_port"] <= 65535
        or type(config["expected_peer_uid"]) is not int
        or config["expected_peer_uid"] != os.getuid()
    ):
        raise SidecarCliError("sidecar launch configuration is unsafe")
    for key in ("socket_path", "cas_root", "cas_key_id", "private_home"):
        if not isinstance(config[key], str) or not config[key]:
            raise SidecarCliError(f"sidecar launch configuration {key} is invalid")
    return config


def _read_nonregular_fd(
    descriptor: int,
    *,
    maximum: int,
    exact: int | None = None,
) -> bytes:
    if type(descriptor) is not int or descriptor < 0:
        raise SidecarCliError("preopened descriptor number is invalid")
    descriptor_stat = os.fstat(descriptor)
    if not _is_pipe_or_connected_local_socket(descriptor, descriptor_stat.st_mode):
        raise SidecarCliError(
            "preopened launch input cannot be an ordinary file or device; "
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
    if len(value) > maximum or (exact is not None and len(value) != exact):
        raise SidecarCliError("preopened launch input has an invalid byte count")
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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
