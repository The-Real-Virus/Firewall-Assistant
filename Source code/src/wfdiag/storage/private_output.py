"""New private directories only. Windows ACL implementation is gated by native validation."""

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from wfdiag.storage.atomic_write import check_plain_path, write_new_bytes

if TYPE_CHECKING:
    from wfdiag.storage.windows_files import WindowsDirectory


def create_private_directory(path: Path) -> "WindowsDirectory | None":
    path = path.absolute()
    check_plain_path(path, allow_missing_leaf=True)
    check_plain_path(path.parent)
    if not path.parent.is_dir():
        raise FileNotFoundError("Select an existing local parent folder")
    if sys.platform == "win32":
        from wfdiag.storage.windows_privacy import WindowsPrivacy

        return WindowsPrivacy().create(path)
    os.mkdir(path, mode=0o700)
    return None


def verify_private_directory(path: Path) -> "WindowsDirectory | None":
    check_plain_path(path)
    if sys.platform == "win32":
        from wfdiag.storage.windows_privacy import WindowsPrivacy

        return WindowsPrivacy().verify_existing(path)
    info = path.stat(follow_symlinks=False)
    if not path.is_dir() or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise PermissionError("A private operator-owned output directory is required")
    return None


def verify_permission_output(path: Path) -> "WindowsDirectory | None":
    """Only the fixed permission collector accepts a prepared, empty private slot."""
    check_plain_path(path)
    check_plain_path(path.parent)
    if sys.platform == "win32":
        from wfdiag.storage.windows_privacy import WindowsPrivacy

        return WindowsPrivacy().verify_permission_output(path)
    held = verify_private_directory(path)
    if any(path.iterdir()):
        raise FileExistsError("Permission collection slot is not empty")
    return held


@contextmanager
def new_analysis_directory(path: Path) -> Iterator[Path]:
    """An interrupted result retains an explicit marker; existing directories are refused."""
    held = create_private_directory(path)
    try:
        write_new_bytes(path / ".incomplete", b'{"status":"incomplete","operation":"analyze"}\n')
        yield path
        if held is not None:
            held.close()
            held = None
        (path / ".incomplete").unlink()
    finally:
        if held is not None:
            held.close()


@contextmanager
def private_parent(path: Path) -> Iterator[None]:
    held = verify_private_directory(path.parent)
    try:
        yield
    finally:
        if held is not None:
            held.close()
