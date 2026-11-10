"""Bounded new-file streaming with the same no-overwrite finalization as byte outputs."""

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Self

from wfdiag.storage.atomic_write import check_plain_path


class NewSource:
    def __init__(self, path: Path, byte_limit: int) -> None:
        check_plain_path(path, allow_missing_leaf=True)
        if path.exists():
            raise FileExistsError("Choose a new source destination")
        self.path, self.byte_limit = path, byte_limit
        self.stream = tempfile.NamedTemporaryFile(  # noqa: SIM115 -- this context manager owns it.
            mode="wb", dir=path.parent, prefix=".wfdiag-", delete=False
        )
        self.temporary = Path(self.stream.name)
        self.byte_length = 0
        self.digest = hashlib.sha256()
        self.finished = False

    def __enter__(self) -> Self:
        return self

    def write(self, data: bytes) -> None:
        if self.finished or self.byte_length + len(data) > self.byte_limit:
            raise ValueError("Source output byte budget exceeded")
        self.stream.write(data)
        self.digest.update(data)
        self.byte_length += len(data)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if exc_type is None:
                self.stream.flush()
                os.fsync(self.stream.fileno())
                self.stream.close()
                check_plain_path(self.path, allow_missing_leaf=True)
                os.link(self.temporary, self.path, follow_symlinks=False)
                self.finished = True
        finally:
            self.stream.close()
            self.temporary.unlink(missing_ok=True)
