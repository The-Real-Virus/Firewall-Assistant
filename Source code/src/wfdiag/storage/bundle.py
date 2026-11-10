"""Validate known case directories and hold opened files through analysis consumption."""

import hashlib
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, BinaryIO, Self

from pydantic import Field, TypeAdapter

from wfdiag.contracts.base import Contract
from wfdiag.contracts.models import (
    CollectionError,
    Event,
    FirewallProfile,
    Host,
    Manifest,
    NetworkSnapshot,
    Rule,
)
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.parsers.firewall_log import MAX_LINE_BYTES
from wfdiag.services.cancellation import CancellationToken
from wfdiag.storage.json_input import checked_json
from wfdiag.storage.opened_files import OpenedDirectory

MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_EVENT_LINE_BYTES = 256 * 1024
MAX_EVENTS = 100000
PROFILE_ADAPTER: TypeAdapter[tuple[FirewallProfile, ...]] = TypeAdapter(
    Annotated[tuple[FirewallProfile, ...], Field(max_length=3)]
)
RULE_ADAPTER: TypeAdapter[tuple[Rule, ...]] = TypeAdapter(
    Annotated[tuple[Rule, ...], Field(max_length=10000)]
)
ERROR_ADAPTER: TypeAdapter[tuple[CollectionError, ...]] = TypeAdapter(
    Annotated[tuple[CollectionError, ...], Field(max_length=1000)]
)


class BundleError(DiagnosticError):
    def __init__(self, message: str, code: ExitCode = ExitCode.INVALID_INPUT) -> None:
        super().__init__(code, message)


@dataclass(frozen=True)
class FileStamp:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def _stamp(stream: BinaryIO) -> FileStamp:
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise BundleError("Case source is not a plain singly linked file.")
    return FileStamp(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _without_bom(data: bytes) -> bytes:
    return data[3:] if data.startswith(b"\xef\xbb\xbf") else data


def _model[T: Contract](model: type[T], data: bytes, limit: int = MAX_SOURCE_BYTES) -> T:
    checked_json(data, byte_limit=limit)
    return model.model_validate_json(_without_bom(data))


class VerifiedBundle:
    """Use as a context manager. Hash consistency is not source authentication."""

    def __init__(self, path: Path, cancellation: CancellationToken | None = None) -> None:
        self.path = path.absolute()
        self.cancellation = cancellation or CancellationToken()
        self._directory: OpenedDirectory | None = None
        self._streams: dict[str, BinaryIO] = {}
        self._stamps: dict[str, FileStamp] = {}
        self.manifest: Manifest
        self.host: Host
        self.profiles: tuple[FirewallProfile, ...]
        self.rules: tuple[Rule, ...]
        self.errors: tuple[CollectionError, ...]
        self.network: NetworkSnapshot | None = None

    def __enter__(self) -> Self:
        try:
            self._load()
            return self
        except PermissionError as exc:
            self.close()
            raise BundleError(
                "Case is inaccessible or in use; obtain a completed private copy.",
                ExitCode.ACCESS_DENIED,
            ) from exc
        except (OSError, ValueError) as exc:
            self.close()
            raise BundleError(
                "Case metadata, source format or file path is invalid; obtain a fresh approved capture."
            ) from exc
        except BaseException:
            self.close()
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _open(self, name: str) -> BinaryIO:
        assert self._directory is not None
        stream = self._directory.open_relative(name)
        self._streams[name] = stream
        self._stamps[name] = _stamp(stream)
        return stream

    def _read(self, name: str, limit: int = MAX_SOURCE_BYTES) -> bytes:
        stream = self._streams[name]
        stream.seek(0)
        data = bytearray()
        while chunk := stream.read(65536):
            self.cancellation.check()
            data.extend(chunk)
            if len(data) > limit:
                raise BundleError("Actual source bytes exceed the input budget.")
        self._check_file(name)
        return bytes(data)

    def _load(self) -> None:
        self.cancellation.check()
        self._directory = OpenedDirectory(self.path)
        self._open("manifest.json")
        self.manifest = _model(
            Manifest, self._read("manifest.json", MAX_MANIFEST_BYTES), MAX_MANIFEST_BYTES
        )
        expected = {"manifest.json", *(f.filename for f in self.manifest.files)}
        self._check_inventory(expected)
        self._load_sources()

    def _check_inventory(self, expected: set[str]) -> None:
        actual = {p.name for p in self.path.iterdir()}
        if actual != expected:
            raise BundleError("Case directory contains missing or unexpected files.")

    def _load_sources(self) -> None:
        total = self._stamps["manifest.json"].size
        for entry in self.manifest.files:
            stream = self._open(entry.filename)
            if self._stamps[entry.filename].size != entry.byte_length:
                raise BundleError("Actual source size does not match the manifest.")
            digest = hashlib.sha256()
            count = 0
            while chunk := stream.read(65536):
                self.cancellation.check()
                count += len(chunk)
                total += len(chunk)
                if count > MAX_SOURCE_BYTES or total > MAX_TOTAL_BYTES:
                    raise BundleError("Actual streamed bytes exceed the input budget.")
                digest.update(chunk)
            if count != entry.byte_length or digest.hexdigest() != entry.sha256:
                raise BundleError("Case source hash or byte length does not match the manifest.")
            self._check_file(entry.filename)
            stream.seek(0)
        self.host = _model(Host, self._read("host.json"))
        if self.host != self.manifest.host:
            raise BundleError("Host metadata conflicts with the manifest.")
        raw = self._read("profiles.json")
        checked_json(raw, byte_limit=MAX_SOURCE_BYTES)
        self.profiles = PROFILE_ADAPTER.validate_json(_without_bom(raw))
        if len({p.profile for p in self.profiles}) != len(self.profiles):
            raise BundleError("Profile records are duplicated.")
        raw = self._read("rules.json")
        checked_json(raw, byte_limit=MAX_SOURCE_BYTES)
        self.rules = RULE_ADAPTER.validate_json(_without_bom(raw))
        if len({r.rule_id.casefold() for r in self.rules}) != len(self.rules):
            raise BundleError("Stable rule identifiers are duplicated.")
        raw = self._read("collection-errors.json")
        checked_json(raw, byte_limit=MAX_SOURCE_BYTES)
        self.errors = ERROR_ADAPTER.validate_json(_without_bom(raw))
        if "network.json" in self._streams:
            self.network = _model(NetworkSnapshot, self._read("network.json"))
        counts = {
            "host": 1,
            "profiles": len(self.profiles),
            "rules": len(self.rules),
            "collection-errors": len(self.errors),
        }
        if self.network is not None:
            counts["network"] = len(self.network.interfaces)
        for source in self.manifest.sources:
            if source.source in counts and source.records != counts[source.source]:
                raise BundleError("Source record count does not match the manifest.")
        self.check_unchanged()

    def iter_events(self) -> Iterator[Event]:
        stream = self._streams["events.ndjson"]
        stream.seek(0)
        records = 0
        lines = 0
        try:
            while line := stream.readline(MAX_EVENT_LINE_BYTES + 1):
                self.cancellation.check()
                lines += 1
                if lines > MAX_EVENTS or len(line) > MAX_EVENT_LINE_BYTES:
                    raise BundleError("Event record or line byte budget exceeded.")
                if not line.strip():
                    continue
                records += 1
                yield _model(Event, line, MAX_EVENT_LINE_BYTES)
            expected = next(s.records for s in self.manifest.sources if s.source == "events")
            if records != expected:
                raise BundleError("Event record count does not match the manifest.")
            self._check_file("events.ndjson")
        except (OSError, ValueError) as exc:
            raise BundleError(
                "Event input is malformed or changed; analysis did not complete."
            ) from exc

    def _check_file(self, name: str) -> None:
        if _stamp(self._streams[name]) != self._stamps[name]:
            raise BundleError("An opened source changed during validation or analysis.")

    def iter_firewall_log_lines(self) -> Iterator[bytes]:
        """Preserve physical line references while bounding the allocation per line."""
        stream = self._streams.get("firewall-log.txt")
        if stream is None:
            return
        stream.seek(0)
        while line := stream.readline(MAX_LINE_BYTES + 1):
            self.cancellation.check()
            if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
                # Drain this one rejected physical line without allocating it in full.
                while rest := stream.readline(MAX_LINE_BYTES + 1):
                    self.cancellation.check()
                    if rest.endswith(b"\n"):
                        break
            yield line
        self._check_file("firewall-log.txt")

    def check_unchanged(self) -> None:
        for name in self._streams:
            self._check_file(name)

    def close(self) -> None:
        for stream in self._streams.values():
            stream.close()
        self._streams.clear()
        if self._directory is not None:
            self._directory.close()
            self._directory = None
