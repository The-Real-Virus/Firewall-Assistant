"""Create a new output atomically; never replace an existing destination."""

import os
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path

from wfdiag.contracts.base import absolute_local_path


def check_plain_path(path: Path, *, allow_missing_leaf: bool = False) -> None:
    absolute_local_path(str(path))
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and component == path:
                continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Symlink or reparse redirection is not accepted")


def write_new_bytes(path: Path, content: bytes, *, byte_limit: int = 1024 * 1024) -> None:
    if len(content) > byte_limit:
        raise ValueError("Output exceeds its byte budget")
    write_new_chunks(path, (content,), byte_limit=byte_limit)


def write_new_chunks(path: Path, chunks: Iterable[bytes], *, byte_limit: int = 1024 * 1024) -> None:
    """Enforce actual streamed bytes; no result becomes visible until complete and flushed."""
    check_plain_path(path, allow_missing_leaf=True)
    if path.exists():
        raise FileExistsError("Output already exists; choose a new destination")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=".wfdiag-", delete=False
        ) as output:
            temporary = Path(output.name)
            count = 0
            for chunk in chunks:
                count += len(chunk)
                if count > byte_limit:
                    raise ValueError("Output exceeds its byte budget")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        # Hard-link creation is atomic and fails if the destination already exists on both
        # supported Windows NTFS and portable development filesystems. Unsupported filesystems
        # fail closed. Private parent ACLs and opened-object checks are a separate contract.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
