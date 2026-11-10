"""Bounded packaged-engine consistency check, performed away from the GUI event loop."""

import hashlib
import os
import re
import sys
from pathlib import Path

from wfdiag.storage.json_input import checked_json
from wfdiag.storage.opened_files import OpenedDirectory
from wfdiag.version import __version__


class EngineInstallationUnavailable(ValueError):
    """Repair the complete matching program folder; never search PATH or a case folder."""


def verify_program_root(root: Path) -> None:
    """Hashes detect inconsistency, not an authenticated publisher or a malicious manifest."""
    directory = OpenedDirectory(root)
    try:
        with directory.open_relative("build-manifest.json") as manifest:
            data = manifest.read(1024 * 1024 + 1)
        record = checked_json(data, byte_limit=1024 * 1024, max_depth=12)
        if not isinstance(record, dict) or record.get("version") != __version__:
            raise ValueError("Unsupported or mismatched program manifest")
        files = record.get("files")
        identity = files.get("wfdiag.exe") if isinstance(files, dict) else None
        if not isinstance(identity, dict) or set(identity) != {"bytes", "sha256"}:
            raise ValueError("Missing packaged engine identity")
        size, expected = identity["bytes"], identity["sha256"]
        if (
            type(size) is not int
            or not 0 < size <= 64 * 1024 * 1024
            or not isinstance(expected, str)
            or re.fullmatch("[a-f0-9]{64}", expected) is None
        ):
            raise ValueError("Invalid bounded engine identity")
        with directory.open_relative("wfdiag.exe") as engine:
            if os.fstat(engine.fileno()).st_size != size:
                raise ValueError("Packaged engine size differs")
            digest = hashlib.sha256()
            read = 0
            while chunk := engine.read(min(65536, size + 1 - read)):
                read += len(chunk)
                if read > size:
                    raise ValueError("Packaged engine exceeds declared size")
                digest.update(chunk)
            if read != size or digest.hexdigest() != expected:
                raise ValueError("Packaged engine hash differs")
    finally:
        directory.close()


def verify_frozen_installation() -> None:
    if not getattr(sys, "frozen", False):
        return
    try:
        verify_program_root(Path(sys.executable).resolve().parent)
    except (OSError, ValueError) as error:
        raise EngineInstallationUnavailable("ENGINE_INSTALLATION_UNAVAILABLE") from error
