#!/usr/bin/env python3
"""Run the candidate command as PID 1 while reaping orphaned descendants."""

from __future__ import annotations

import ctypes
import os
import signal
import sys
import time

_PR_SET_CHILD_SUBREAPER = 36
_GRACE_SECONDS = 2.0


def _exit_code(status: int) -> int:
    return os.waitstatus_to_exitcode(status)


def _set_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _signal_group(child: int, signum: int) -> None:
    try:
        os.killpg(child, signum)
    except ProcessLookupError:
        pass


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: phase5e_pid1_reaper.py COMMAND...", file=sys.stderr)
        return 2

    _set_subreaper()
    child = os.fork()
    if child == 0:
        os.setsid()
        os.execvp(argv[1], argv[1:])

    forwarded_signal: int | None = None

    def forward(signum: int, _frame: object) -> None:
        nonlocal forwarded_signal
        forwarded_signal = signum
        _signal_group(child, signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, forward)

    child_status: int | None = None
    while child_status is None:
        try:
            pid, status = os.wait()
        except InterruptedError:
            continue
        if pid == child:
            child_status = status

    _signal_group(child, signal.SIGTERM)
    deadline = time.monotonic() + _GRACE_SECONDS
    while time.monotonic() < deadline:
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        time.sleep(0.01)
    else:
        _signal_group(child, signal.SIGKILL)

    while True:
        try:
            os.wait()
        except InterruptedError:
            continue
        except ChildProcessError:
            break

    if forwarded_signal is not None and _exit_code(child_status) == 0:
        return 128 + forwarded_signal
    return _exit_code(child_status)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
