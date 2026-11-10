"""Environment-free architecture and ARM-emulation regression, no WMI/evidence calls."""

import ctypes
import sys
from ctypes import wintypes

import pytest

from wfdiag.collectors.architecture import native_architecture


@pytest.mark.parametrize(
    ("native", "expected"), [(0x8664, "x64"), (0xAA64, "arm64"), (0x014C, "x86"), (0, "unknown")]
)
def test_os_architecture_is_not_inferred_from_environment_or_process(
    native, expected, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("PROCESSOR_ARCHITECTURE", raising=False)
    monkeypatch.setenv("PROCESSOR_ARCHITEW6432", "DELIBERATELY_FALSE")

    class Function:
        def __init__(self, call):
            self.call = call

        def __call__(self, *args):
            return self.call(*args)

    def query(handle, process, host):
        assert handle == -1
        ctypes.cast(process, ctypes.POINTER(wintypes.WORD)).contents.value = 0x8664
        ctypes.cast(host, ctypes.POINTER(wintypes.WORD)).contents.value = native
        return 1

    class API:
        GetCurrentProcess = Function(lambda: -1)
        IsWow64Process2 = Function(query)

    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: API(), raising=False)
    assert native_architecture() == expected


def test_unavailable_windows_api_preserves_unknown(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")

    def denied(*args, **kwargs):
        raise OSError("CANARY_PRIVATE_ERROR")

    monkeypatch.setattr(ctypes, "WinDLL", denied, raising=False)
    assert native_architecture() == "unknown"
