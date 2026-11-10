import subprocess
import sys
from pathlib import Path
from typing import BinaryIO

from wfdiag.collectors import process_runner
from wfdiag.services.cancellation import CancellationToken


class BrokenRead:
    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    def read(self, size: int) -> bytes:
        raise OSError("Synthetic read failure")

    def close(self) -> None:
        self.stream.close()


def test_read_failure_cannot_be_an_empty_success(tmp_path: Path, monkeypatch: object) -> None:
    import pytest

    assert isinstance(monkeypatch, pytest.MonkeyPatch)
    original = subprocess.Popen

    def injected(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = original(*args, **kwargs)
        assert process.stdout is not None
        process.stdout = BrokenRead(process.stdout)
        return process

    monkeypatch.setattr(process_runner.subprocess, "Popen", injected)
    result = process_runner._bounded_process(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        cwd=tmp_path,
        cancellation=CancellationToken(),
    )
    assert result.read_failed
    assert result.stdout == b""
