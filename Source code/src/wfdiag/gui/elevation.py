"""User-clicked Windows consent for the fixed read-only sibling collector only."""

import ctypes
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

from wfdiag.contracts.base import absolute_local_path
from wfdiag.gui.installation import verify_frozen_installation


class PermissionDeclined(OSError):
    """Windows consent was cancelled; no successful collection is inferred."""


class ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


class PermissionProcess:
    def __init__(self, handle: int) -> None:
        self.handle = handle
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL

    def poll(self) -> int | None:
        code = wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise OSError("Administrator collector status is unavailable")
        return None if code.value == 259 else int(code.value)

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = 0


def request_collection(out: Path, minutes: int, owner: int) -> PermissionProcess:
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        raise OSError("Windows permission collection requires the complete packaged application")
    absolute_local_path(str(out))
    if not 1 <= minutes <= 60:
        raise ValueError("Lookback must be1–60 minutes")
    verify_frozen_installation()
    executable = Path(sys.executable).resolve().parent / "wfdiag.exe"
    args = ["permission-collect", "--minutes", str(minutes), "--out", str(out)]
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40 | 0x100 | 0x400  # Owned process handle, synchronous launch, own error UI.
    info.hwnd = owner
    info.lpVerb = "runas"
    info.lpFile = str(executable)
    info.lpParameters = subprocess.list2cmdline(args)
    info.lpDirectory = str(executable.parent)
    info.nShow = 0  # Background collector; GUI supplies progress and cooperative Cancel.
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        if ctypes.get_last_error() == 1223:
            raise PermissionDeclined("Windows permission request was cancelled")
        raise OSError("Windows could not start the administrator collector")
    if not info.hProcess:
        raise OSError("Windows did not return the collector process handle")
    return PermissionProcess(int(info.hProcess))
