"""Bounded local NDJSON worker over the shared services. No Qt or AI imports."""

import os
import sys
from pathlib import Path
from threading import Event, Lock, Thread
from typing import BinaryIO, Literal
from uuid import UUID

from wfdiag.contracts.desktop_job import (
    EVENT_ADAPTER,
    MAX_CONTROL_BYTES,
    MAX_FRAME_BYTES,
    MAX_REQUEST_BYTES,
    CancelControl,
    CancelledEvent,
    CancelledPayload,
    CompletedEvent,
    CompletedPayload,
    DesktopEvent,
    DesktopRequest,
    FailedEvent,
    FailedPayload,
    ProgressEvent,
    ProgressPayload,
    StartedEvent,
    StartedPayload,
    decode_request,
)
from wfdiag.contracts.enums import Completeness
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.services import operations
from wfdiag.services.cancellation import CancellationToken, Cancelled
from wfdiag.services.interfaces import ProgressSink
from wfdiag.storage.atomic_write import check_plain_path
from wfdiag.storage.json_input import checked_json
from wfdiag.storage.opened_files import OpenedDirectory
from wfdiag.storage.private_output import verify_private_directory
from wfdiag.version import __version__


def execute_desktop(
    request: DesktopRequest, cancellation: CancellationToken, progress: ProgressSink
) -> Completeness:
    # A doctor report can be successfully generated while reporting unavailable
    # capabilities. CLI retains its readiness exit code; the desktop must still
    # display the actual validated report rather than leaving "not run" on screen.
    from wfdiag.contracts.doctor import DoctorReport
    from wfdiag.storage.records import read_record

    try:
        return operations.execute(request, cancellation, progress)
    except DiagnosticError as error:
        if request.operation != "doctor" or error.code not in (
            ExitCode.UNSUPPORTED,
            ExitCode.ACCESS_DENIED,
        ):
            raise
        try:
            report = read_record(Path(request.parameters.out), DoctorReport, byte_limit=1024 * 1024)
            if report.engine_version != __version__:
                raise ValueError("Wrong preflight report version")
        except (OSError, ValueError, DiagnosticError):
            raise error from None
        return Completeness.COMPLETE


DEADLINES = {
    "doctor": 135,
    "collect": 400,
    "analyze": 90,
    "report": 90,
    "propose": 30,
    "compare": 90,
}


class Emitter:
    def __init__(self, job_id: str, output: BinaryIO) -> None:
        self.job_id = job_id
        self.output = output
        self.sequence = 0
        self.total = 0
        self.terminal = False
        self.lock = Lock()

    def send(self, event: DesktopEvent) -> None:
        with self.lock:
            if self.terminal:
                raise ValueError("Terminal worker output already emitted")
            event = EVENT_ADAPTER.validate_python(event)
            line = (event.model_dump_json() + "\n").encode("utf-8")
            if len(line) - 1 > MAX_FRAME_BYTES:
                raise ValueError("Worker frame byte budget exceeded")
            if (
                event.type in ("progress", "warning")
                and self.total + len(line) > MAX_CONTROL_BYTES - 2 * MAX_FRAME_BYTES
            ):
                return  # Reserve bounded space for completion/failure; progress can be coalesced.
            if self.total + len(line) > MAX_CONTROL_BYTES:
                raise ValueError("Worker control byte budget exceeded")
            if event.job_id != self.job_id or event.sequence != self.sequence + 1:
                raise ValueError("Worker event identity or sequence mismatch")
            self.output.write(line)
            self.output.flush()
            self.total += len(line)
            self.sequence = event.sequence
            self.terminal = event.type in ("completed", "failed", "cancelled")

    def progress(self, stage: str, completed: int | None, total: int | None) -> None:
        self.send(
            ProgressEvent(
                job_id=self.job_id,
                sequence=self.sequence + 1,
                type="progress",
                payload=ProgressPayload(
                    stage=stage,
                    completed_units=completed if total is not None else None,
                    total_units=total,
                ),
            )
        )


def _control(job_id: str, cancellation: CancellationToken, finished: Event) -> None:
    pending = bytearray()
    received = 0
    try:
        while not finished.is_set():
            # Direct descriptor reads avoid a daemon holding Python's buffered-stdin lock
            # during interpreter shutdown. EOF means the owning GUI disconnected.
            chunk = os.read(0, 1024)
            if not chunk:
                cancellation.request()
                return
            received += len(chunk)
            pending.extend(chunk)
            if received > 4096 or len(pending) > 2048:
                raise ValueError("Cancel control exceeded its budget")
            while b"\n" in pending:
                line, _, remaining = pending.partition(b"\n")
                pending = bytearray(remaining)
                checked_json(bytes(line), byte_limit=2048, max_depth=4, max_values=32)
                control = CancelControl.model_validate_json(bytes(line))
                if control.job_id != job_id:
                    raise ValueError("Cancel control job mismatch")
                cancellation.request()
                return
    except (OSError, ValueError):
        cancellation.request()  # Malformed controls cannot continue a job.


def _watchdog(cancellation: CancellationToken, finished: Event, seconds: int) -> None:
    if not finished.wait(seconds):
        cancellation.request()
        if not finished.wait(8):
            # A wedged worker cannot report success. Process exit closes its private
            # collector-job handles; the parent treats missing terminal output as failure.
            os._exit(int(ExitCode.INCOMPLETE))


def run_desktop_job(path: Path) -> int:
    try:
        return _run_desktop_job(path)
    except FileNotFoundError as exc:
        raise DiagnosticError(ExitCode.INVALID_INPUT, "Private worker request is missing.") from exc
    except PermissionError as exc:
        raise DiagnosticError(
            ExitCode.ACCESS_DENIED, "Private worker request access could not be verified."
        ) from exc
    except OSError as exc:
        raise DiagnosticError(
            ExitCode.INTERNAL, "Worker input or process communication failed."
        ) from exc


def _run_desktop_job(path: Path) -> int:
    """Only a fresh private UUID job directory/request.json is accepted."""
    check_plain_path(path)
    if path.name != "request.json":
        raise ValueError("Use the private request filename")
    privacy = verify_private_directory(path.parent)
    directory = None
    try:
        directory = OpenedDirectory(path.parent)
        with directory.open_relative(path.name) as source:
            data = source.read(MAX_REQUEST_BYTES + 1)
        request = decode_request(data)
        identifier = UUID(request.job_id)
        if (
            identifier.version != 4
            or str(identifier) != request.job_id
            or path.parent.name != request.job_id
        ):
            raise ValueError("Private request identity does not match its directory")
        emitter = Emitter(request.job_id, sys.stdout.buffer)
        emitter.send(
            StartedEvent(
                job_id=request.job_id,
                sequence=1,
                type="started",
                payload=StartedPayload(engine_version=__version__),
            )
        )
        cancellation = CancellationToken()
        finished = Event()
        Thread(target=_control, args=(request.job_id, cancellation, finished), daemon=True).start()
        Thread(
            target=_watchdog,
            args=(cancellation, finished, DEADLINES[request.operation]),
            daemon=True,
        ).start()
        try:
            completeness = execute_desktop(request, cancellation, emitter.progress)
            cancellation.check()
            completion_code: Literal[0, 5] = 0 if completeness == Completeness.COMPLETE else 5
            emitter.send(
                CompletedEvent(
                    job_id=request.job_id,
                    sequence=emitter.sequence + 1,
                    type="completed",
                    payload=CompletedPayload(
                        output=request.parameters.out,
                        completeness=completeness,
                        exit_code=completion_code,
                    ),
                )
            )
            return completion_code
        except Cancelled:
            emitter.send(
                CancelledEvent(
                    job_id=request.job_id,
                    sequence=emitter.sequence + 1,
                    type="cancelled",
                    payload=CancelledPayload(cleanup_confirmed=True),
                )
            )
            return int(ExitCode.INCOMPLETE)
        except DiagnosticError as exc:
            code = int(exc.code)
            if code not in (2, 3, 4, 5, 6):
                code = 6
            payload = FailedPayload.model_validate({"code": "OPERATION_FAILED", "exit_code": code})
            emitter.send(
                FailedEvent(
                    job_id=request.job_id,
                    sequence=emitter.sequence + 1,
                    type="failed",
                    payload=payload,
                )
            )
            return code
        except Exception:  # noqa: BLE001 -- Process boundary never discloses source/exception data.
            emitter.send(
                FailedEvent(
                    job_id=request.job_id,
                    sequence=emitter.sequence + 1,
                    type="failed",
                    payload=FailedPayload(code="PROCESSING_FAILED", exit_code=6),
                )
            )
            return int(ExitCode.INTERNAL)
        finally:
            finished.set()
    finally:
        if directory is not None:
            directory.close()
        if privacy is not None:
            privacy.close()
