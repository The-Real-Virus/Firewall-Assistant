import ctypes
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from pathlib import Path
from threading import Timer

import pytest

from wfdiag.collectors.process_runner import _bounded_process
from wfdiag.services.cancellation import CancellationToken


def test_capture_drains_stdout_and_stderr(tmp_path: Path) -> None:
    result = _bounded_process(
        [sys.executable, "-c", "import sys; print('ok'); print('warning',file=sys.stderr)"],
        cwd=tmp_path,
        cancellation=CancellationToken(),
    )
    assert result.return_code == 0
    assert result.stdout.strip() == b"ok"
    assert result.stderr.strip() == b"warning"
    assert not result.timed_out and not result.output_truncated


def test_actual_output_overflow_is_bounded(tmp_path: Path) -> None:
    result = _bounded_process(
        [sys.executable, "-c", "import sys; sys.stdout.write('x'*4000000)"],
        cwd=tmp_path,
        cancellation=CancellationToken(),
        output_limit=1024,
    )
    assert result.output_truncated
    assert len(result.stdout) == 1024


def test_timeout_stops_owned_process(tmp_path: Path) -> None:
    start = time.monotonic()
    result = _bounded_process(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        cwd=tmp_path,
        cancellation=CancellationToken(),
        timeout=0.2,
    )
    assert result.timed_out
    assert time.monotonic() - start < 5


def test_cancel_stops_owned_process(tmp_path: Path) -> None:
    token = CancellationToken()
    timer = Timer(0.2, token.request)
    timer.start()
    try:
        result = _bounded_process(
            [sys.executable, "-c", "import time; time.sleep(20)"], cwd=tmp_path, cancellation=token
        )
        assert result.cancelled
    finally:
        timer.join()


@pytest.mark.windows
@pytest.mark.skipif(
    sys.platform != "win32", reason="Native owned-process job test requires Windows"
)
def test_timeout_reaps_owned_descendant(tmp_path: Path) -> None:
    code = "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)']); print(child.pid,flush=True); time.sleep(20)"
    result = _bounded_process(
        [sys.executable, "-c", code], cwd=tmp_path, cancellation=CancellationToken(), timeout=1
    )
    assert result.timed_out
    child_pid = int(result.stdout.strip())
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    handle = api.OpenProcess(0x00100000 | 0x1000, False, child_pid)
    if not handle:
        assert ctypes.get_last_error() == 87
    else:
        try:
            assert api.WaitForSingleObject(handle, 0) == 0
        finally:
            api.CloseHandle(handle)


@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="Native owned-job cleanup observation")
def test_normal_root_exit_reaps_child_before_returning(tmp_path: Path) -> None:
    code = "import subprocess,sys; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)']); print(child.pid,flush=True)"
    result = _bounded_process(
        [sys.executable, "-c", code], cwd=tmp_path, cancellation=CancellationToken(), timeout=5
    )
    assert result.return_code == 0 and not result.timed_out
    child_pid = int(result.stdout.strip())
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.OpenProcess(0x00100000 | 0x1000, False, child_pid)
    if handle:
        try:
            assert api.WaitForSingleObject(handle, 0) == 0
        finally:
            api.CloseHandle(handle)
    else:
        assert ctypes.get_last_error() == 87


@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="Native concurrent owned-job observation")
def test_parallel_timeouts_leave_a_separate_test_process_alive(tmp_path: Path) -> None:
    code = "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)']); print(child.pid,flush=True); time.sleep(20)"
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def run(index: int):
        return _bounded_process(
            [sys.executable, "-c", code], cwd=tmp_path, cancellation=CancellationToken(), timeout=3
        )

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(run, range(4)))
        assert all(result.timed_out and result.stdout.strip().isdigit() for result in results)
        assert unrelated.poll() is None
    finally:
        unrelated.kill()
        unrelated.wait(timeout=5)
