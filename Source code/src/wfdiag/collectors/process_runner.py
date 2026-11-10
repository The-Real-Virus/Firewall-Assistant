"""Bounded capture and owned process lifetime for fixed collector resources."""

import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from typing import BinaryIO

from wfdiag.services.cancellation import CancellationToken


@dataclass(frozen=True)
class ProcessResult:
    stdout: bytes
    stderr: bytes
    return_code: int
    timed_out: bool
    cancelled: bool
    output_truncated: bool
    read_failed: bool
    stdout_bytes: int = 0


def _bounded_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    cancellation: CancellationToken,
    timeout: float = 120,
    output_limit: int = 1024 * 1024,
    environment: Mapping[str, str] | None = None,
    stdout_consumer: Callable[[bytes], None] | None = None,
) -> ProcessResult:
    """Internal primitive. Only fixed resource wrappers may call it in shipped services."""
    if not argv or not Path(argv[0]).is_absolute() or timeout <= 0 or output_limit < 1:
        raise ValueError("Invalid fixed-process configuration")
    cancellation.check()
    job = None
    flags = 0
    if sys.platform == "win32":
        from wfdiag.collectors.windows_job import WindowsJob

        job = WindowsJob()
        flags = 0x08000000 | 0x4  # CREATE_NO_WINDOW | CREATE_SUSPENDED.
    process: subprocess.Popen[bytes] | None = None
    stdout, stderr = bytearray(), bytearray()
    overflow = Event()
    read_failure = Event()
    readers: list[Thread] = []
    timed_out = False
    cancelled = False
    stdout_bytes = 0

    def drain(stream: BinaryIO, destination: bytearray, *, standard_output: bool) -> None:
        nonlocal stdout_bytes
        observed = 0
        limit = output_limit if standard_output else min(output_limit, 1024 * 1024)
        rejected = False
        try:
            while chunk := stream.read(8192):
                remaining = limit - observed
                observed += len(chunk)
                if standard_output:
                    stdout_bytes = observed
                bounded = chunk[: max(0, remaining)]
                if standard_output and stdout_consumer is not None:
                    if not rejected and bounded:
                        try:
                            stdout_consumer(bounded)
                        except Exception:  # noqa: BLE001 -- callback failure rejects the capture.
                            rejected = True
                            read_failure.set()
                else:
                    destination.extend(bounded)
                if len(chunk) > remaining:
                    overflow.set()
        except (OSError, ValueError):
            read_failure.set()
        finally:
            stream.close()

    try:
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=flags,
            close_fds=True,
        )
        if job is not None:
            job.assign_and_resume(process)
        assert process.stdout is not None and process.stderr is not None
        for stream, destination, is_stdout in (
            (process.stdout, stdout, True),
            (process.stderr, stderr, False),
        ):
            reader = Thread(
                target=drain,
                args=(stream, destination),
                kwargs={"standard_output": is_stdout},
                daemon=True,
            )
            reader.start()
            readers.append(reader)
        while process.poll() is None:
            cancelled = cancellation.requested
            timed_out = time.monotonic() >= deadline
            if cancelled or timed_out or overflow.is_set() or read_failure.is_set():
                if job is not None:
                    job.close()
                else:
                    process.kill()
                break
            try:
                process.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                continue
        if job is not None:
            job.close()  # Reap descendants even after normal root exit.
        process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise OSError("Owned output pipes did not close within the cleanup bound")
        return ProcessResult(
            bytes(stdout),
            bytes(stderr),
            process.returncode,
            timed_out,
            cancelled,
            overflow.is_set(),
            read_failure.is_set(),
            stdout_bytes,
        )
    finally:
        if job is not None:
            job.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=5)
