from __future__ import annotations

import argparse
import os
import re
import resource
import signal
import socket
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

from .canonical import SidecarContractError, expected_resolved_local_path
from .supervisor import serve_attestor

CONFIG_FD = 3
CAS_KEY_FD = 4
SIGNER_SEED_FD = 5
RUNTIME_AUTHORIZATION_FD = 6
AUTHORIZATION_KEYRING_FD = 7
CHILD_SIGNER_FD = 5
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")


class LauncherError(SidecarContractError):
    """Raised when the fixed rootless supervisor launch contract is invalid."""


def build_parser(*, prog: str = "owner-research-futu-launch") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument("--signer-key-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    return _main(argv, prog="owner-research-futu-launch")


def preopen_and_launch_main(argv: Sequence[str] | None = None) -> int:
    return _main(argv, prog="owner-research-futu-preopen-and-launch")


def _main(argv: Sequence[str] | None, *, prog: str) -> int:
    arguments = build_parser(prog=prog).parse_args(argv)
    if os.geteuid() == 0:
        print(f"{prog}: root execution is forbidden", file=sys.stderr)
        return 2
    if _KEY_ID.fullmatch(arguments.signer_key_id) is None:
        print(f"{prog}: signer key ID is invalid", file=sys.stderr)
        return 2
    try:
        _activate_rootless_environment()
        for descriptor in (
            CONFIG_FD,
            CAS_KEY_FD,
            SIGNER_SEED_FD,
            RUNTIME_AUTHORIZATION_FD,
            AUTHORIZATION_KEYRING_FD,
        ):
            _validate_preopened_descriptor(descriptor)
        return _launch(arguments.signer_key_id)
    except (OSError, SidecarContractError) as exc:
        print(f"{prog}: {exc}", file=sys.stderr)
        return 2


def _activate_rootless_environment() -> None:
    private_home_value = os.environ.get("OWNER_RESEARCH_FUTU_PRIVATE_HOME")
    if not private_home_value:
        raise LauncherError("private per-run HOME is required")
    private_home = Path(private_home_value)
    try:
        metadata = private_home.lstat()
        resolved_home = private_home.resolve(strict=True)
    except OSError as exc:
        raise LauncherError("private per-run HOME is unavailable") from exc
    if (
        not private_home.is_absolute()
        or resolved_home != expected_resolved_local_path(private_home)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
    ):
        raise LauncherError(
            "private per-run HOME must be a real mode-0700 directory owned by this UID"
        )
    private_home = resolved_home
    os.environ["HOME"] = os.fspath(private_home)
    os.environ["XDG_CACHE_HOME"] = os.fspath(private_home / ".cache")
    os.environ["XDG_CONFIG_HOME"] = os.fspath(private_home / ".config")
    os.environ["XDG_DATA_HOME"] = os.fspath(private_home / ".local" / "share")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True
    os.umask(0o077)
    _, hard_limit = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, hard_limit))


def _validate_preopened_descriptor(descriptor: int) -> None:
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise LauncherError(f"required preopened descriptor {descriptor} is unavailable") from exc
    if not _is_pipe_or_connected_local_socket(descriptor, metadata.st_mode):
        raise LauncherError(
            f"preopened descriptor {descriptor} must be a one-shot pipe or local socket"
        )


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


def _launch(signer_key_id: str) -> int:
    parent_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - exercised by installed smoke test
        try:
            parent_socket.close()
            os.close(SIGNER_SEED_FD)
            os.close(RUNTIME_AUTHORIZATION_FD)
            os.close(AUTHORIZATION_KEYRING_FD)
            if child_socket.fileno() != CHILD_SIGNER_FD:
                os.dup2(child_socket.fileno(), CHILD_SIGNER_FD, inheritable=True)
                child_socket.close()
            else:
                os.set_inheritable(CHILD_SIGNER_FD, True)
            os.set_inheritable(CONFIG_FD, True)
            os.set_inheritable(CAS_KEY_FD, True)
            os.execv(
                sys.executable,
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-m",
                    "owner_research_futu_sidecar.cli",
                    "serve",
                    "--config-fd",
                    str(CONFIG_FD),
                    "--cas-key-fd",
                    str(CAS_KEY_FD),
                    "--signer-fd",
                    str(CHILD_SIGNER_FD),
                ],
            )
        except BaseException:
            os._exit(127)
    child_socket.close()
    os.close(CONFIG_FD)
    os.close(CAS_KEY_FD)

    def forward_signal(signum: int, _: object) -> None:
        try:
            os.kill(child_pid, signum)
        except ProcessLookupError:
            pass

    previous_term = signal.signal(signal.SIGTERM, forward_signal)
    previous_int = signal.signal(signal.SIGINT, forward_signal)
    try:
        serve_attestor(
            signer_socket=parent_socket,
            seed_fd=SIGNER_SEED_FD,
            authorization_fd=RUNTIME_AUTHORIZATION_FD,
            authorization_keyring_fd=AUTHORIZATION_KEYRING_FD,
            signer_key_id=signer_key_id,
        )
    except BaseException:
        try:
            os.kill(child_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
    _, status = os.waitpid(child_pid, 0)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    raise LauncherError("sidecar child exited with an unknown status")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ("main", "preopen_and_launch_main")
