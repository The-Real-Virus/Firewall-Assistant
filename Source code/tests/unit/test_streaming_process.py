"""Harmless owned processes exercise streaming and sink-failure cleanup."""

import sys
from pathlib import Path

from wfdiag.collectors.process_runner import _bounded_process
from wfdiag.services.cancellation import CancellationToken


def test_stream_consumer_does_not_retain_stdout(tmp_path: Path) -> None:
    seen = 0
    largest = 0

    def consume(chunk: bytes) -> None:
        nonlocal seen, largest
        seen += len(chunk)
        largest = max(largest, len(chunk))

    result = _bounded_process(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*3000000)"],
        cwd=tmp_path,
        cancellation=CancellationToken(),
        output_limit=4000000,
        stdout_consumer=consume,
    )
    assert result.return_code == 0 and not result.read_failed
    assert seen == result.stdout_bytes == 3000000
    assert largest <= 8192 and result.stdout == b""


def test_stream_budget_and_callback_failure_cannot_succeed(tmp_path: Path) -> None:
    def broken(chunk: bytes) -> None:
        raise ValueError("Synthetic rejected frame")

    result = _bounded_process(
        [sys.executable, "-c", "import sys,time; print('x',flush=True); time.sleep(20)"],
        cwd=tmp_path,
        cancellation=CancellationToken(),
        timeout=2,
        stdout_consumer=broken,
    )
    assert result.read_failed and result.stdout == b""
    received = bytearray()
    capped = _bounded_process(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*3000000)"],
        cwd=tmp_path,
        cancellation=CancellationToken(),
        output_limit=8193,
        stdout_consumer=received.extend,
    )
    assert capped.output_truncated and len(received) <= 8193 and not capped.stdout
