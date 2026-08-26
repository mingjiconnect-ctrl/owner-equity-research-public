from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .canonical import SidecarContractError


class SecureReadError(SidecarContractError):
    """Raised when a bounded trust-root file changes or follows a link."""


@dataclass(slots=True)
class ReadBudget:
    maximum_bytes: int
    used_bytes: int = 0

    def consume(self, count: int) -> None:
        if type(count) is not int or count < 0:
            raise SecureReadError("read-budget count is invalid")
        if self.used_bytes + count > self.maximum_bytes:
            raise SecureReadError("cumulative file reads exceed the byte budget")
        self.used_bytes += count


def read_bounded_snapshot(
    path: Path,
    *,
    maximum_bytes: int,
    budget: ReadBudget | None = None,
) -> bytes:
    """Read one regular file without links and replay its inode before/after."""

    path = Path(path)
    if not path.is_absolute() or maximum_bytes <= 0:
        raise SecureReadError("bounded snapshot path or limit is invalid")
    try:
        path_before = path.lstat()
    except OSError as exc:
        raise SecureReadError("bounded snapshot path is unavailable") from exc
    if not stat.S_ISREG(path_before.st_mode) or path_before.st_nlink != 1:
        raise SecureReadError("bounded snapshot must be one non-linked regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SecureReadError("bounded snapshot file cannot be opened without following") from exc
    try:
        before = os.fstat(descriptor)
        _same_file(path_before, before)
        if before.st_size < 0 or before.st_size > maximum_bytes:
            raise SecureReadError("bounded snapshot file exceeds its per-file limit")
        if budget is not None and budget.used_bytes + before.st_size > budget.maximum_bytes:
            raise SecureReadError("bounded snapshot exceeds its cumulative read budget")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > maximum_bytes:
            raise SecureReadError("bounded snapshot grew beyond its per-file limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or len(value) != after.st_size
        ):
            raise SecureReadError("bounded snapshot changed while it was read")
        try:
            path_after = path.lstat()
        except OSError as exc:
            raise SecureReadError("bounded snapshot path disappeared during the read") from exc
        _same_file(after, path_after)
    finally:
        os.close(descriptor)
    if budget is not None:
        budget.consume(len(value))
    return value


def _same_file(left: os.stat_result, right: os.stat_result) -> None:
    if (
        not stat.S_ISREG(right.st_mode)
        or right.st_nlink != 1
        or left.st_dev != right.st_dev
        or left.st_ino != right.st_ino
    ):
        raise SecureReadError("bounded snapshot path was rebound")


__all__ = ("ReadBudget", "SecureReadError", "read_bounded_snapshot")
