"""Fully validate large GUI results, retaining offsets rather than every finding graph.

The index is a local view resource, never an engine result or export. Its metadata has
no findings; read_page returns only the explicitly requested view page. CLI/report/
proposal services continue to consume the original complete analysis independently.
"""

import hashlib
import os
from array import array
from collections.abc import Iterator
from pathlib import Path
from threading import RLock
from typing import BinaryIO

from wfdiag.contracts.models import Analysis, Finding
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.storage.analysis_json import analysis_data_from_checked_json
from wfdiag.storage.atomic_write import check_plain_path
from wfdiag.storage.json_input import checked_json
from wfdiag.storage.opened_files import OpenedDirectory
from wfdiag.storage.records import MAX_ANALYSIS_BYTES, RecordByteBudgetExceeded, read_analysis

PAGE_SIZE = 500
INDEX_THRESHOLD_BYTES = 4 * 1024 * 1024
MAX_PAGE_BATCH_BYTES = 4 * 1024 * 1024


def _identity(stream: BinaryIO) -> tuple[int, int, int, int, int]:
    info = os.fstat(stream.fileno())
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _complete(directory: Path) -> None:
    try:
        (directory / ".incomplete").lstat()
    except FileNotFoundError:
        return
    raise DiagnosticError(ExitCode.INVALID_INPUT, "The analysis directory is incomplete.")


def _fields(analysis: Analysis) -> dict[str, object]:
    return {name: getattr(analysis, name) for name in Analysis.model_fields}


class AnalysisIndex:
    """Own one held plain file; page reads and closing serialize across local workers."""

    def __init__(
        self,
        directory: OpenedDirectory,
        stream: BinaryIO,
        identity: tuple[int, int, int, int, int],
        metadata: Analysis,
        offsets: array[int],
        sha256: str,
    ) -> None:
        self._directory = directory
        self._stream = stream
        self._identity = identity
        self.metadata = metadata
        self._offsets = offsets
        self.sha256 = sha256
        self._lock = RLock()
        self.first_page = self.read_page(0)

    @property
    def count(self) -> int:
        return len(self._offsets) // 2

    def _check(self) -> None:
        if self._stream.closed or _identity(self._stream) != self._identity:
            raise ValueError("Indexed analysis is closed or changed")
        if os.fstat(self._stream.fileno()).st_nlink != 1:
            raise ValueError("Indexed analysis must remain singly linked")
        _complete(self._directory.path)

    def read_page(self, page: int) -> Analysis:
        if type(page) is not int or page < 0 or page > max(0, (self.count - 1) // PAGE_SIZE):
            raise ValueError("Invalid analysis page")
        with self._lock:
            self._check()
            findings = []
            first, stop = page * PAGE_SIZE, min((page + 1) * PAGE_SIZE, self.count)
            base = self._offsets[first * 2] if first < stop else 0
            end = self._offsets[(stop - 1) * 2 + 1] if first < stop else 0
            block = None
            if 0 < end - base <= MAX_PAGE_BATCH_BYTES:
                self._stream.seek(base)
                block = self._stream.read(end - base)
                if len(block) != end - base:
                    raise ValueError("Indexed page bytes changed")
            for index in range(first, stop):
                start, end = self._offsets[index * 2 : index * 2 + 2]
                if block is not None:
                    raw = block[start - base : end - base]
                else:
                    # Huge inter-record whitespace must not force a huge page buffer.
                    self._stream.seek(start)
                    raw = self._stream.read(end - start)
                if len(raw) != end - start:
                    raise ValueError("Indexed finding bytes changed")
                findings.append(Finding.model_validate_json(raw))
            self._check()
            return Analysis.model_validate(
                {**_fields(self.metadata), "findings": tuple(findings)}, strict=True
            )

    def iter_pages(self) -> Iterator[Analysis]:
        """For full-case privacy review on its worker; never silently select one page."""
        for page in range(max(1, (self.count + PAGE_SIZE - 1) // PAGE_SIZE)):
            yield self.read_page(page)

    def close(self) -> None:
        with self._lock:
            self._stream.close()
            self._directory.close()


def open_analysis_index(path: Path) -> AnalysisIndex:
    """Validate every byte and finding, global uniqueness and unchanged Analysis rules.

    A single eligible witness exercises Analysis's cross-finding/context eligibility
    invariants. Those rules depend on existence, never the number of eligible findings.
    Global IDs/count are checked independently while every Finding validates unchanged.
    No unvalidated off-page data is accepted. Keep this contract aligned with Analysis.
    """
    check_plain_path(path)
    target = path / "analysis.json" if path.is_dir() else path
    _complete(target.parent)
    directory = OpenedDirectory(target.parent, allow_child_writes=True)
    stream: BinaryIO | None = None
    try:
        stream = directory.open_relative(target.name)
        before = _identity(stream)
        if before[2] > MAX_ANALYSIS_BYTES:
            raise ValueError("Analysis byte budget exceeded")
        data = bytearray()
        while chunk := stream.read(65536):
            data.extend(chunk)
            if len(data) > MAX_ANALYSIS_BYTES:
                raise ValueError("Actual analysis bytes exceed the budget")
        raw = bytes(data)
        del data
        sha256 = hashlib.sha256(raw).hexdigest()
        checked_json(
            raw,
            byte_limit=MAX_ANALYSIS_BYTES,
            max_depth=32,
            max_values=10000000,
            retain_objects=False,
        )
        byte_cursor = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
        text = raw.decode("utf-8-sig", errors="strict")
        del raw
        character_cursor = 0
        offsets = array("Q")
        ids: set[str] = set()
        eligible: Finding | None = None

        def consume(finding: Finding, start: int, end: int) -> None:
            nonlocal character_cursor, byte_cursor, eligible
            if finding.finding_id in ids:
                raise ValueError("Finding IDs must be distinct")
            ids.add(finding.finding_id)
            byte_cursor += len(text[character_cursor:start].encode("utf-8"))
            offsets.append(byte_cursor)
            byte_cursor += len(text[start:end].encode("utf-8"))
            offsets.append(byte_cursor)
            character_cursor = end
            if finding.proposal_eligible and eligible is None:
                eligible = finding

        fields = analysis_data_from_checked_json(
            text, finding_consumer=consume, retain_findings=False
        )
        metadata = Analysis.model_validate(fields, strict=True)
        if eligible is not None:
            Analysis.model_validate({**fields, "findings": (eligible,)}, strict=True)
        if _identity(stream) != before:
            raise ValueError("Opened analysis changed while indexing")
        _complete(target.parent)
        return AnalysisIndex(directory, stream, before, metadata, offsets, sha256)
    except BaseException:
        if stream is not None:
            stream.close()
        directory.close()
        raise


def read_gui_analysis(path: Path) -> Analysis | AnalysisIndex:
    # Decide from the held file and actual byte count, never a pathname stat followed
    # by a differently opened full-model read. A replacement cannot evade the small
    # path's cap. Indexing independently reopens and validates the entire held input.
    try:
        return read_analysis(path, byte_limit=INDEX_THRESHOLD_BYTES)
    except RecordByteBudgetExceeded:
        return open_analysis_index(path)
