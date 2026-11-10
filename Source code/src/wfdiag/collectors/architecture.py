"""Read native Windows architecture without WMI or inherited environment guesses."""

import ctypes
import sys
from ctypes import wintypes
from typing import Literal

Architecture = Literal["x64", "x86", "arm64", "unknown"]


MACHINES: dict[int, Architecture] = {0x8664: "x64", 0x014C: "x86", 0xAA64: "arm64"}


def native_architecture() -> Architecture:
    if sys.platform != "win32":
        return "unknown"
    try:
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        # Windows10 1709+, before our1809 baseline. Native machine distinguishes
        # ARM64 emulation; pointer size/environment/WMI do not establish OS arch.
        api.GetCurrentProcess.argtypes = []
        api.GetCurrentProcess.restype = wintypes.HANDLE
        api.IsWow64Process2.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.WORD),
        ]
        api.IsWow64Process2.restype = wintypes.BOOL
        process_machine, native_machine = wintypes.WORD(), wintypes.WORD()
        if not api.IsWow64Process2(
            api.GetCurrentProcess(), ctypes.byref(process_machine), ctypes.byref(native_machine)
        ):
            return "unknown"
        return MACHINES.get(native_machine.value, "unknown")
    except (OSError, AttributeError):
        return "unknown"
