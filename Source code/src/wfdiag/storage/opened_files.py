"""Hold input identities through validation and consumption; never trust path strings alone."""

import os
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from wfdiag.storage.windows_files import WindowsDirectory

from wfdiag.storage.atomic_write import check_plain_path


class OpenedDirectory:
    def __init__(self, path: Path, *, allow_child_writes: bool = False) -> None:
        check_plain_path(path)
        if not path.is_dir():
            raise ValueError("A case directory is required")
        self.path = path
        self._descriptor: int | None = None
        self._windows: WindowsDirectory | None = None
        if sys.platform == "win32":
            from wfdiag.storage.windows_files import WindowsDirectory as NativeWindowsDirectory

            self._windows = (
                NativeWindowsDirectory(path, allow_child_writes=True)
                if allow_child_writes
                else NativeWindowsDirectory(path)
            )
        else:
            before = path.stat(follow_symlinks=False)
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(descriptor)
                raise ValueError("Case directory identity changed while opening")
            self._descriptor = descriptor

    def open_relative(self, name: str) -> BinaryIO:
        if not name or name in (".", "..") or any(c in name for c in ("/", "\\", ":", "\x00")):
            raise ValueError("Invalid source filename")
        if self._windows is not None:
            return self._windows.open_relative(name)
        if self._descriptor is None:
            raise ValueError("Case directory is closed")
        if sys.platform == "win32":
            raise ValueError("Windows case directory handle is unavailable")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(descriptor)
            raise ValueError("Source must be a plain singly linked file")
        try:
            return os.fdopen(descriptor, "rb", buffering=65536)
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        if self._windows is not None:
            self._windows.close()
        if self._descriptor is not None:
            descriptor, self._descriptor = self._descriptor, None
            os.close(descriptor)
