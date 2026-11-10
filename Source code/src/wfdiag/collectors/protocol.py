"""Private fixed-resource stream. Malformed or unfinished output cannot become complete."""

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, TypeAdapter, model_validator

from wfdiag.contracts.base import Contract, Identifier, actual_integer
from wfdiag.contracts.models import UTC, Host, NetworkInterface
from wfdiag.parsers.policy_json import NativeFields, NativeRule
from wfdiag.storage.json_input import checked_json

Source = Literal["host", "network", "profiles", "rules", "events"]
MAX_FRAME_BYTES = 512 * 1024


class FrameBase(Contract):
    protocol_version: Annotated[Literal[1], BeforeValidator(actual_integer)]
    source: Source
    at_utc: UTC


class StartedFrame(FrameBase):
    kind: Literal["started"]
    window_start_utc: UTC | None
    window_end_utc: UTC | None

    @model_validator(mode="after")
    def coherent_window(self) -> "StartedFrame":
        if (self.window_start_utc is None) != (self.window_end_utc is None):
            raise ValueError("Both window bounds are required")
        if (
            self.window_start_utc is not None
            and self.window_end_utc is not None
            and self.window_start_utc > self.window_end_utc
        ):
            raise ValueError("Invalid source window")
        return self


class RecordFrame(FrameBase):
    kind: Literal["record"]
    data: (
        NativeRule
        | NativeFields
        | Host
        | NetworkInterface
        | Annotated[str, Field(max_length=65536)]
    )


class FinishedFrame(FrameBase):
    kind: Literal["finished"]
    state: Literal[
        "complete",
        "empty",
        "unavailable",
        "access_denied",
        "error",
        "truncated",
        "cancelled",
        "unsupported",
    ]
    count: Annotated[int, Field(ge=0, le=100000), BeforeValidator(actual_integer)]
    codes: Annotated[tuple[Identifier, ...], Field(max_length=100)]


CollectionFrame = Annotated[StartedFrame | RecordFrame | FinishedFrame, Field(discriminator="kind")]
FRAME_ADAPTER: TypeAdapter[CollectionFrame] = TypeAdapter(CollectionFrame)


class CollectionStream:
    def __init__(
        self, sources: tuple[Source, ...], consume: Callable[[CollectionFrame], None]
    ) -> None:
        self.sources, self.consume = sources, consume
        self.buffer = bytearray()
        self.index = 0
        self.started: StartedFrame | None = None
        self.records = 0
        self.rejected = False
        self.first = True
        self.last_at: datetime | None = None

    def feed(self, data: bytes) -> None:
        if self.rejected:
            raise ValueError("Collector stream already rejected")
        try:
            self.buffer.extend(data)
            start = 0
            while (end := self.buffer.find(b"\n", start)) >= 0:
                line = bytes(self.buffer[start:end]).removesuffix(b"\r")
                start = end + 1
                if self.first:
                    line = line.removeprefix(b"\xef\xbb\xbf")
                    self.first = False
                checked_json(line, byte_limit=MAX_FRAME_BYTES, max_depth=16, max_values=20000)
                frame = FRAME_ADAPTER.validate_json(line)
                self.accept(frame)
            if start:
                del self.buffer[:start]
            if len(self.buffer) > MAX_FRAME_BYTES:
                raise ValueError("Collector frame exceeds budget")
        except (ValueError, UnicodeError):
            self.rejected = True
            self.buffer.clear()
            raise

    def accept(self, frame: CollectionFrame) -> None:
        if self.last_at is not None and frame.at_utc < self.last_at:
            raise ValueError("Collector timestamps move backwards")
        self.last_at = frame.at_utc
        if self.index >= len(self.sources) or frame.source != self.sources[self.index]:
            raise ValueError("Unexpected collector source order")
        if isinstance(frame, StartedFrame):
            if self.started is not None:
                raise ValueError("Duplicate collector start")
            self.started = frame
            self.records = 0
        elif self.started is None or frame.at_utc < self.started.at_utc:
            raise ValueError("Collector record outside a started source")
        elif isinstance(frame, RecordFrame):
            limit = {"host": 1, "network": 512, "profiles": 3, "rules": 10000, "events": 100000}[
                frame.source
            ]
            self.records += 1
            if self.records > limit:
                raise ValueError("Collector record cap exceeded")
        else:
            if frame.count != self.records or (frame.state == "empty" and self.records):
                raise ValueError("Collector completion count disagrees")
            if frame.state == "complete" and not self.records:
                raise ValueError("An empty source must be explicitly empty")
            self.started = None
            self.index += 1
        self.consume(frame)

    def finish(self) -> None:
        if (
            self.rejected
            or self.buffer
            or self.started is not None
            or self.index != len(self.sources)
        ):
            self.rejected = True
            raise ValueError("Collector stream ended without every source completion")
