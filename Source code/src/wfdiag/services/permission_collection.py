"""Read-only elevated collector entry; no request files or arbitrary operations."""

import re
import time
from pathlib import Path

from wfdiag.collectors.capture import collect_native_case
from wfdiag.contracts.base import absolute_local_path
from wfdiag.contracts.enums import Completeness
from wfdiag.services.cancellation import CancellationToken
from wfdiag.storage.opened_files import OpenedDirectory


class PermissionCancellation(CancellationToken):
    def __init__(self, parent: OpenedDirectory, name: str) -> None:
        super().__init__()
        self.parent, self.name = parent, name
        self.deadline = time.monotonic() + 420

    @property
    def requested(self) -> bool:
        if super().requested or time.monotonic() >= self.deadline:
            return True
        try:
            with self.parent.open_relative(self.name):
                return True
        except FileNotFoundError:
            return False
        except OSError:
            return True  # A changed/unreadable control is cancellation, never authority.


def permission_collect(out: Path, minutes: int) -> Completeness:
    absolute_local_path(str(out))
    if (
        not re.fullmatch(r"permission-case-[a-f0-9-]{36}", out.name)
        or type(minutes) is not int
        or not 1 <= minutes <= 60
    ):
        raise ValueError("Invalid fixed permission collection arguments")
    parent = OpenedDirectory(out.parent)
    try:
        token = PermissionCancellation(parent, out.name + ".cancel")
        token.check()
        return collect_native_case(
            out, minutes, token, lambda *_: None, permission_directory=True
        ).completeness
    finally:
        parent.close()
