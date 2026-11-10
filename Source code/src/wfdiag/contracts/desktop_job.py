"""Local desktop requests/events, independent of Qt and AI."""

from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BeforeValidator, Field, TypeAdapter, model_validator

from wfdiag.contracts.base import (
    Contract,
    Identifier,
    PathText,
    ShortText,
    absolute_local_path,
    actual_integer,
)
from wfdiag.contracts.enums import Completeness
from wfdiag.storage.json_input import checked_json

AbsolutePath = Annotated[PathText, AfterValidator(absolute_local_path)]
JobId = Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,64}$")]
MAX_FRAME_BYTES = 16 * 1024
MAX_CONTROL_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
ProtocolVersion = Annotated[Literal[1], BeforeValidator(actual_integer)]


class DoctorParameters(Contract):
    out: AbsolutePath


class CollectParameters(DoctorParameters):
    minutes: Annotated[int, Field(ge=1, le=60)] = 10


class AnalyzeParameters(DoctorParameters):
    bundle: AbsolutePath
    intent: AbsolutePath | None = None


class ReportParameters(DoctorParameters):
    analysis: AbsolutePath
    mode: Literal["share", "full"]


class ProposeParameters(DoctorParameters):
    analysis: AbsolutePath
    finding_id: Identifier
    intent: AbsolutePath


class CompareParameters(DoctorParameters):
    before: AbsolutePath
    after: AbsolutePath


class RequestBase(Contract):
    protocol_version: ProtocolVersion = 1
    job_id: JobId
    expected_engine_version: Annotated[
        str,
        Field(
            pattern=r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|\.dev\d+|[-+][A-Za-z0-9.-]+)?$", max_length=64
        ),
    ]


class DoctorJob(RequestBase):
    operation: Literal["doctor"]
    parameters: DoctorParameters


class CollectJob(RequestBase):
    operation: Literal["collect"]
    parameters: CollectParameters


class AnalyzeJob(RequestBase):
    operation: Literal["analyze"]
    parameters: AnalyzeParameters


class ReportJob(RequestBase):
    operation: Literal["report"]
    parameters: ReportParameters


class ProposeJob(RequestBase):
    operation: Literal["propose"]
    parameters: ProposeParameters


class CompareJob(RequestBase):
    operation: Literal["compare"]
    parameters: CompareParameters


DesktopRequest = Annotated[
    DoctorJob | CollectJob | AnalyzeJob | ReportJob | ProposeJob | CompareJob,
    Field(discriminator="operation"),
]
REQUEST_ADAPTER: TypeAdapter[DesktopRequest] = TypeAdapter(DesktopRequest)


class StartedPayload(Contract):
    engine_version: Identifier


class ProgressPayload(Contract):
    stage: Identifier
    completed_units: Annotated[int, Field(ge=0)] | None = None
    total_units: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def denominator_is_real(self) -> Self:
        if (self.completed_units is None) != (self.total_units is None):
            raise ValueError("Progress needs both counts or neither")
        if (
            self.completed_units is not None
            and self.total_units is not None
            and self.completed_units > self.total_units
        ):
            raise ValueError("Progress cannot exceed its denominator")
        return self


class WarningPayload(Contract):
    code: Identifier
    message: ShortText


class CompletedPayload(Contract):
    output: AbsolutePath
    completeness: Completeness
    exit_code: Annotated[Literal[0, 5], BeforeValidator(actual_integer)]

    @model_validator(mode="after")
    def completeness_agrees(self) -> Self:
        if (self.exit_code == 0) != (self.completeness == Completeness.COMPLETE):
            raise ValueError("Completion and exit code disagree")
        return self


class FailedPayload(Contract):
    code: Identifier
    exit_code: Annotated[Literal[2, 3, 4, 5, 6], BeforeValidator(actual_integer)]


class CancelledPayload(Contract):
    cleanup_confirmed: bool


class EventBase(Contract):
    protocol_version: ProtocolVersion = 1
    job_id: JobId
    sequence: Annotated[int, Field(ge=1, le=1000000)]


class StartedEvent(EventBase):
    type: Literal["started"]
    payload: StartedPayload


class ProgressEvent(EventBase):
    type: Literal["progress"]
    payload: ProgressPayload


class WarningEvent(EventBase):
    type: Literal["warning"]
    payload: WarningPayload


class CompletedEvent(EventBase):
    type: Literal["completed"]
    payload: CompletedPayload


class FailedEvent(EventBase):
    type: Literal["failed"]
    payload: FailedPayload


class CancelledEvent(EventBase):
    type: Literal["cancelled"]
    payload: CancelledPayload


DesktopEvent = Annotated[
    StartedEvent | ProgressEvent | WarningEvent | CompletedEvent | FailedEvent | CancelledEvent,
    Field(discriminator="type"),
]
EVENT_ADAPTER: TypeAdapter[DesktopEvent] = TypeAdapter(DesktopEvent)


class CancelControl(Contract):
    protocol_version: ProtocolVersion = 1
    job_id: JobId
    type: Literal["cancel"]


def decode_request(data: bytes) -> DesktopRequest:
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("Desktop request exceeds its byte budget")
    checked_json(data, byte_limit=MAX_REQUEST_BYTES, max_depth=12, max_values=4096)
    return REQUEST_ADAPTER.validate_json(data)


class EventDecoder:
    """Incremental stream validation; cannot turn an invalid stream into success."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self._buffer = bytearray()
        self._total = 0
        self._sequence = 0
        self._started = False
        self._terminal = False
        self._failed = False

    def feed(self, data: bytes) -> tuple[DesktopEvent, ...]:
        if self._failed:
            raise ValueError("Desktop stream was already rejected")
        try:
            return self._feed(data)
        except (ValueError, UnicodeError):
            self._failed = True
            self._buffer.clear()
            raise

    def _feed(self, data: bytes) -> tuple[DesktopEvent, ...]:
        self._total += len(data)
        if self._total > MAX_CONTROL_BYTES:
            raise ValueError("Desktop control output exceeds budget")
        self._buffer.extend(data)
        result: list[DesktopEvent] = []
        while b"\n" in self._buffer:
            line, _, remainder = self._buffer.partition(b"\n")
            self._buffer = bytearray(remainder)
            if not line or len(line) > MAX_FRAME_BYTES:
                raise ValueError("Invalid desktop frame size")
            line.decode("utf-8", errors="strict")
            checked_json(bytes(line), byte_limit=MAX_FRAME_BYTES, max_depth=12, max_values=512)
            event = EVENT_ADAPTER.validate_json(bytes(line))
            if (
                self._terminal
                or event.job_id != self.job_id
                or event.sequence != self._sequence + 1
            ):
                raise ValueError("Unexpected desktop event identity, order or terminal state")
            if not self._started and event.type != "started":
                raise ValueError("Desktop stream must start with started")
            if self._started and event.type == "started":
                raise ValueError("Duplicate desktop start")
            self._started = True
            self._sequence = event.sequence
            self._terminal = event.type in ("completed", "failed", "cancelled")
            result.append(event)
        if len(self._buffer) > MAX_FRAME_BYTES:
            raise ValueError("Unterminated desktop frame exceeds budget")
        return tuple(result)

    def finish(self) -> None:
        if self._failed or self._buffer or not self._terminal:
            self._failed = True
            raise ValueError("Desktop stream ended without a valid terminal event")
