from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from owner_research_futu_sidecar.attestation import (
    Ed25519Attestor,
    SessionController,
)
from owner_research_futu_sidecar.canonical import SidecarContractError, canonical_bytes, utc_now
from owner_research_futu_sidecar.launcher import (
    LauncherError,
    _activate_rootless_environment,
    _validate_preopened_descriptor,
)
from owner_research_futu_sidecar.operation_registry import (
    PINNED_SDK_SDIST_SHA256,
    PINNED_SDK_VERSION,
    PROTOBUF_DESCRIPTOR_SET_SHA256,
    SDK_ADAPTER_REGISTRY_SHA256,
)
from owner_research_futu_sidecar.runtime_authorization import (
    verify_runtime_authorization,
)
from owner_research_futu_sidecar.supervisor import (
    SupervisorAttestorClient,
    SupervisorError,
    _SigningPolicy,
    serve_attestor,
)

from .auth_helpers import (
    authority_fds,
    open_expectations,
    runtime_claims,
    signed_runtime_authority,
)


def test_preopened_supervisor_signs_without_seed_in_data_client() -> None:
    seed = b"\x31" * 32
    identity = Ed25519Attestor.from_private_bytes(seed, signer_key_id="supervisor-key")
    seed_read, seed_write = os.pipe()
    os.write(seed_write, seed)
    os.close(seed_write)
    supervisor_socket, client_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    failures: list[BaseException] = []
    authorization, keyring = signed_runtime_authority(
        run_id="run:test-supervisor", sidecar_signer_key_id="supervisor-key"
    )
    authorization_fd, keyring_fd = authority_fds(authorization, keyring)

    def supervise() -> None:
        try:
            serve_attestor(
                signer_socket=supervisor_socket,
                seed_fd=seed_read,
                authorization_fd=authorization_fd,
                authorization_keyring_fd=keyring_fd,
                signer_key_id="supervisor-key",
            )
        except BaseException as exc:  # test thread must propagate
            failures.append(exc)

    thread = threading.Thread(target=supervise, daemon=True)
    thread.start()
    client = SupervisorAttestorClient(
        signer_socket=client_socket,
        expected_signer_key_id="supervisor-key",
        expected_public_key_hex=identity.public_key_hex,
    )
    supply = _supply()
    controller = SessionController(
        attestor=client,
        supply_attestation=supply,
        runtime_claims=runtime_claims(authorization=authorization),
    )
    boot = controller.open(
        run_id="run:test-supervisor",
        challenge_nonce="supervisor-challenge-0123456789abcdef",
        expected_supply_attestation=supply,
        **open_expectations(authorization),
        startup_checkpoint=_checkpoint("startup", 1),
    )
    Ed25519Attestor.verify(boot, public_key_hex=identity.public_key_hex)
    aborted = controller.abort(
        boot_receipt_id=boot["receipt_id"],
        sequence=1,
        reason_code="caller_abort",
    )
    Ed25519Attestor.verify(aborted, public_key_hex=identity.public_key_hex)
    client.close()
    thread.join(timeout=3)
    assert failures == []


def test_supervisor_rejects_forged_partial_boot_receipt_without_losing_abort_path() -> None:
    seed = b"\x33" * 32
    identity = Ed25519Attestor.from_private_bytes(seed, signer_key_id="supervisor-key")
    seed_read, seed_write = os.pipe()
    os.write(seed_write, seed)
    os.close(seed_write)
    supervisor_socket, client_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    failure: list[BaseException] = []
    authorization, keyring = signed_runtime_authority(
        run_id="run:test-supervisor", sidecar_signer_key_id="supervisor-key"
    )
    authorization_fd, keyring_fd = authority_fds(authorization, keyring)

    def supervise() -> None:
        try:
            serve_attestor(
                signer_socket=supervisor_socket,
                seed_fd=seed_read,
                authorization_fd=authorization_fd,
                authorization_keyring_fd=keyring_fd,
                signer_key_id="supervisor-key",
            )
        except BaseException as exc:  # expected fail-closed termination
            failure.append(exc)

    thread = threading.Thread(target=supervise, daemon=True)
    thread.start()
    client = SupervisorAttestorClient(
        signer_socket=client_socket,
        expected_signer_key_id="supervisor-key",
        expected_public_key_hex=identity.public_key_hex,
    )
    with pytest.raises(SidecarContractError, match="unexpected member set"):
        client.sign(
            {
                "schema_version": "1.0.0",
                "receipt_kind": "futu-sidecar-boot-attestation",
                "run_id": "run:forged",
            }
        )
    client.close()
    thread.join(timeout=3)
    assert failure == []


@pytest.mark.parametrize(
    ("run_id", "sequence"),
    [("run:another", 1), ("run:test-policy", 2)],
)
def test_supervisor_rejects_cross_run_and_skipped_fetch_commitments(
    run_id: str, sequence: int
) -> None:
    seed = b"\x34" * 32
    identity = Ed25519Attestor.from_private_bytes(seed, signer_key_id="policy-key")
    authorization, keyring = signed_runtime_authority(
        run_id="run:test-policy", sidecar_signer_key_id="policy-key"
    )
    controller = SessionController(
        attestor=identity,
        supply_attestation=_supply(),
        runtime_claims=runtime_claims(authorization=authorization),
    )
    boot = controller.open(
        run_id="run:test-policy",
        challenge_nonce="policy-challenge-0123456789abcdef",
        expected_supply_attestation=_supply(),
        **open_expectations(authorization),
        startup_checkpoint=_checkpoint("startup", 1),
    )
    policy = _SigningPolicy(
        signer_key_id="policy-key",
        public_key_hex=identity.public_key_hex,
        authorization=verify_runtime_authorization(
            authorization_raw=canonical_bytes(authorization),
            keyring_raw=canonical_bytes(keyring),
            expected_sidecar_attestor_key_id="policy-key",
        ),
    )
    unsigned_boot = dict(boot)
    unsigned_boot.pop("signature_hex")
    policy.authorize(unsigned_boot, evidence_context=None)
    request = {
        "protocol_version": "1.0.0",
        "command": "authorize_fetch",
        "run_id": run_id,
        "session_id": boot["session_id"],
        "boot_receipt_id": boot["receipt_id"],
        "sequence": sequence,
        "request_id": "request:forged",
        "request_fingerprint": "9" * 64,
        "security_code": "US.AAPL",
        "protocol_id": 3243,
        "parameters_sha256": authorization["request_plan"][0]["parameters_sha256"],
        "page_index": 0,
        "page_key_sha256": None,
        "plan_index": 0,
    }
    with pytest.raises(SupervisorError, match="independently verified authority"):
        policy.authorize_fetch_request(request)


def test_supervisor_rejects_unobserved_final_receipts() -> None:
    authorization, keyring = signed_runtime_authority(
        run_id="run:test-policy", sidecar_signer_key_id="policy-key"
    )
    policy = _SigningPolicy(
        signer_key_id="policy-key",
        public_key_hex="0" * 64,
        authorization=verify_runtime_authorization(
            authorization_raw=canonical_bytes(authorization),
            keyring_raw=canonical_bytes(keyring),
            expected_sidecar_attestor_key_id="policy-key",
        ),
    )
    with pytest.raises(SupervisorError, match="outside finalization"):
        policy.authorize(
            {
                "receipt_kind": "futu-sidecar-execution-attestation",
                "signature_algorithm": "ed25519",
                "signer_key_id": "policy-key",
            },
            evidence_context=None,
        )
    with pytest.raises(SupervisorError, match="outside finalization"):
        policy.authorize(
            {
                "rootless": True,
                "signature_algorithm": "ed25519",
                "signer_key_id": "policy-key",
            },
            evidence_context=None,
        )


def test_supervisor_rejects_regular_seed_file(tmp_path: Path) -> None:
    seed_file = tmp_path / "seed"
    seed_file.write_bytes(b"\x32" * 32)
    descriptor = os.open(seed_file, os.O_RDONLY)
    supervisor_socket, client_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    authorization, keyring = signed_runtime_authority(
        run_id="run:test-supervisor", sidecar_signer_key_id="supervisor-key"
    )
    authorization_fd, keyring_fd = authority_fds(authorization, keyring)
    try:
        with pytest.raises(SupervisorError, match="ordinary file"):
            serve_attestor(
                signer_socket=supervisor_socket,
                seed_fd=descriptor,
                authorization_fd=authorization_fd,
                authorization_keyring_fd=keyring_fd,
                signer_key_id="supervisor-key",
            )
    finally:
        os.close(descriptor)
        supervisor_socket.close()
        client_socket.close()


def test_cli_imports_no_futu_before_runtime_tree_verification() -> None:
    source = Path(__file__).parents[1] / "src"
    environment = {**os.environ, "PYTHONPATH": os.fspath(source)}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import owner_research_futu_sidecar.cli; "
                "assert not any(x == 'futu' or x.startswith('futu.') for x in sys.modules)"
            ),
        ],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_installed_preopen_launcher_is_callable() -> None:
    executable = Path(sys.executable).parent / "owner-research-futu-preopen-and-launch"
    assert executable.is_file()
    result = subprocess.run(
        [executable, "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "--signer-key-id" in result.stdout


def test_launcher_accepts_only_preopened_pipe_or_local_socket(tmp_path: Path) -> None:
    pipe_read, pipe_write = os.pipe()
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    internet_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    internet_listener.bind(("127.0.0.1", 0))
    internet_listener.listen(1)
    internet_client = socket.create_connection(internet_listener.getsockname())
    internet_server, _ = internet_listener.accept()
    ordinary = tmp_path / "ordinary"
    ordinary.write_bytes(b"secret")
    file_descriptor = os.open(ordinary, os.O_RDONLY)
    device_descriptor = os.open(os.devnull, os.O_RDONLY)
    try:
        _validate_preopened_descriptor(pipe_read)
        _validate_preopened_descriptor(left.fileno())
        with pytest.raises(LauncherError, match="pipe or local socket"):
            _validate_preopened_descriptor(file_descriptor)
        with pytest.raises(LauncherError, match="pipe or local socket"):
            _validate_preopened_descriptor(device_descriptor)
        with pytest.raises(LauncherError, match="pipe or local socket"):
            _validate_preopened_descriptor(internet_server.fileno())
    finally:
        os.close(pipe_read)
        os.close(pipe_write)
        left.close()
        right.close()
        os.close(file_descriptor)
        os.close(device_descriptor)
        internet_client.close()
        internet_server.close()
        internet_listener.close()


def test_launcher_private_home_must_be_exact_owner_only_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_home = tmp_path / "private-home"
    private_home.mkdir(mode=0o700)
    monkeypatch.setenv("OWNER_RESEARCH_FUTU_PRIVATE_HOME", os.fspath(private_home))
    _activate_rootless_environment()
    assert os.environ["HOME"] == os.fspath(private_home)
    assert os.environ["PYTHONDONTWRITEBYTECODE"] == "1"

    os.chmod(private_home, 0o755)
    with pytest.raises(LauncherError, match="mode-0700"):
        _activate_rootless_environment()
    os.chmod(private_home, 0o700)
    linked = tmp_path / "linked-home"
    linked.symlink_to(private_home, target_is_directory=True)
    monkeypatch.setenv("OWNER_RESEARCH_FUTU_PRIVATE_HOME", os.fspath(linked))
    with pytest.raises(LauncherError, match="mode-0700"):
        _activate_rootless_environment()


def _supply() -> dict[str, object]:
    return {
        "supply_receipt_fingerprint": "a" * 64,
        "provider_id": "futu-opend-official",
        "provider_version": "1.0.0.dev0",
        "opend_version": "10.10.7008",
        "opend_server_version": 101007008,
        "opend_server_build_no": 1,
        "futu_api_version": PINNED_SDK_VERSION,
        "futu_api_distribution_sha256": PINNED_SDK_SDIST_SHA256,
        "sdk_operation_registry_sha256": SDK_ADAPTER_REGISTRY_SHA256,
        "protobuf_descriptor_set_sha256": PROTOBUF_DESCRIPTOR_SET_SHA256,
        "protocol_descriptor_sha256": "b" * 64,
        "facade_sha256": "c" * 64,
        "adapter_sha256": "d" * 64,
        "parser_sha256": "e" * 64,
    }


def _checkpoint(kind: str, serial: int) -> dict[str, object]:
    return {
        "checkpoint": kind,
        "protocol_id": 1002,
        "serial_number": serial,
        "global_state_request_fingerprint": "7" * 64,
        "global_state_response_fingerprint": "8" * 64,
        "observed_at": utc_now(),
        "qot_logined": True,
        "trd_logined": False,
        "opend_server_version": 101007008,
        "opend_server_build_no": 1,
    }
