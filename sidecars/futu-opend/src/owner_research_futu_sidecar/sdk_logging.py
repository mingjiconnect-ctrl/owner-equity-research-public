from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from types import ModuleType
from typing import Any

from .canonical import SidecarContractError

_FUTU_LOG_RELATIVE = Path(".com.futunn.FutuOpenD") / "Log"
_MAXIMUM_TRANSIENT_LOG_BYTES = 1024 * 1024


class FutuSdkLogError(SidecarContractError):
    """Raised when the official SDK cannot be held inside a silent private HOME."""


class FutuSdkLogBoundary:
    def __init__(self, *, private_home: Path) -> None:
        home = Path(private_home)
        try:
            home_stat = home.lstat()
        except OSError as exc:
            raise FutuSdkLogError("private SDK HOME is unavailable") from exc
        if (
            not home.is_absolute()
            or home.resolve(strict=True) != home
            or not stat.S_ISDIR(home_stat.st_mode)
            or home_stat.st_uid != os.getuid()
            or stat.S_IMODE(home_stat.st_mode) != 0o700
        ):
            raise FutuSdkLogError("private SDK HOME must be an exact owner-only directory")
        self.private_home = home
        self.log_directory = home / _FUTU_LOG_RELATIVE
        self._logger: Any | None = None

    def activate_environment(self) -> None:
        value = os.fspath(self.private_home)
        os.environ["HOME"] = value
        os.environ["XDG_CACHE_HOME"] = os.fspath(self.private_home / ".cache")
        os.environ["XDG_CONFIG_HOME"] = os.fspath(self.private_home / ".config")
        os.environ["XDG_DATA_HOME"] = os.fspath(self.private_home / ".local" / "share")

    def silence(self, module: ModuleType) -> None:
        logger = getattr(module, "logger", None)
        if logger is None:
            raise FutuSdkLogError("pinned Futu SDK logger singleton is unavailable")
        for target_name in ("file_logger", "console_logger"):
            target = getattr(logger, target_name, None)
            if not isinstance(target, logging.Logger):
                raise FutuSdkLogError("pinned Futu SDK logger shape changed")
            for handler in tuple(target.handlers):
                if isinstance(handler, logging.FileHandler):
                    handler_path = Path(handler.baseFilename)
                    if (
                        handler_path.parent != self.log_directory
                        or handler_path.is_symlink()
                    ):
                        raise FutuSdkLogError(
                            "Futu SDK logging started outside the private HOME"
                        )
                target.removeHandler(handler)
                handler.close()
            target.addHandler(logging.NullHandler())
            target.setLevel(logging.CRITICAL + 1)
            target.propagate = False
        logger.fileHandler = logging.NullHandler()
        logger.consoleHandler = logging.NullHandler()
        logger._file_level = logging.CRITICAL + 1
        logger._console_level = logging.CRITICAL + 1
        self._remove_transient_files()
        self._logger = logger
        self.assert_quiescent()

    def assert_quiescent(self) -> None:
        if self._logger is None:
            raise FutuSdkLogError("Futu SDK logging boundary was not activated")
        for target_name in ("file_logger", "console_logger"):
            target = getattr(self._logger, target_name)
            if (
                target.level != logging.CRITICAL + 1
                or target.propagate
                or len(target.handlers) != 1
                or not isinstance(target.handlers[0], logging.NullHandler)
            ):
                raise FutuSdkLogError("Futu SDK logging was re-enabled")
        if self.log_directory.exists():
            try:
                members = tuple(self.log_directory.iterdir())
            except OSError as exc:
                raise FutuSdkLogError("Futu SDK log directory cannot be replayed") from exc
            if members:
                raise FutuSdkLogError("Futu SDK left a persistent log member")

    def _remove_transient_files(self) -> None:
        if not self.log_directory.exists():
            return
        try:
            directory_stat = self.log_directory.lstat()
            members = tuple(self.log_directory.iterdir())
        except OSError as exc:
            raise FutuSdkLogError("Futu SDK transient log directory is unsafe") from exc
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or self.log_directory.resolve(strict=True) != self.log_directory
            or directory_stat.st_uid != os.getuid()
        ):
            raise FutuSdkLogError("Futu SDK transient log directory was rebound")
        for member in members:
            member_stat = member.lstat()
            if (
                not stat.S_ISREG(member_stat.st_mode)
                or member_stat.st_uid != os.getuid()
                or member_stat.st_nlink != 1
                or member_stat.st_size > _MAXIMUM_TRANSIENT_LOG_BYTES
            ):
                raise FutuSdkLogError("Futu SDK created an unsafe transient log member")
            member.unlink()


__all__ = ("FutuSdkLogBoundary", "FutuSdkLogError")
