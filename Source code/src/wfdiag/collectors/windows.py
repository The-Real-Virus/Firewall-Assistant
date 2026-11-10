"""Fixed Windows resources and current native-device observations; no mutation APIs."""

import ctypes
import hashlib
import sys
from collections.abc import Callable
from contextlib import ExitStack, closing
from datetime import datetime, timedelta
from importlib.resources import as_file, files
from pathlib import Path
from typing import Literal

from wfdiag.collectors.failures import ResourceIntegrityError
from wfdiag.collectors.process_runner import ProcessResult, _bounded_process
from wfdiag.services.cancellation import CancellationToken
from wfdiag.storage.atomic_write import check_plain_path
from wfdiag.storage.opened_files import OpenedDirectory

ResourceId = Literal["preflight", "host", "policy", "events"]
RESOURCES: dict[ResourceId, str] = {
    "preflight": "Preflight.ps1",
    "host": "Collect-Host.ps1",
    "policy": "Collect-Policy.ps1",
    "events": "Collect-Events.ps1",
}

# Reviewed source contents (LF/CRLF normalized only). Hold read-only handles
# through process completion so checked scripts cannot be replaced or written.
RESOURCE_SHA256 = {
    "Collect-Events.ps1": "c2a4b27799038b94da55f485362db41eb30fff09b6086dd43c6527b50d6d3962",
    "Collect-Host.ps1": "d5cf76b9fede880736df4c5019bef4bb2709dbebfd1d3466091721873292c5ed",
    "Collect-Policy.ps1": "997de52bd6de54da3db64635265e6aa5bea8eb4c4c3bec4e4dea496e3e2951b8",
    "Collection.Common.ps1": "7807dab865e3778fb595ff54515f3906266f352ef95c82079037a5d44fa08375",
    "Preflight.ps1": "978fc732433472006012fe00da63febb0af1db963e9eaeffea4490bdf68ae48b",
}


def system_directory() -> Path:
    if sys.platform != "win32":
        raise OSError("Native Windows collection is unavailable")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    api.GetSystemDirectoryW.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    size = api.GetSystemDirectoryW(buffer, len(buffer))
    if size == 0 or size >= len(buffer):
        raise OSError("System directory resolution failed")
    return Path(buffer.value)


def collector_policy_arguments() -> list[str]:
    """Use the approved default-client mode without lowering an explicit local policy."""
    if sys.platform != "win32":
        return ["-ExecutionPolicy", "RemoteSigned"]  # Only reachable in nonnative doubles.
    import winreg

    path = r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, path) as key:
                policy = str(winreg.QueryValueEx(key, "ExecutionPolicy")[0]).casefold()
            if policy in ("restricted", "allsigned"):
                return []
        except FileNotFoundError:
            continue
        except OSError:
            return []  # Unknown local policy cannot authorize an override.
    # MachinePolicy/UserPolicy are enforced by PowerShell above this process scope.
    return ["-ExecutionPolicy", "RemoteSigned"]


def run_resource(
    resource: ResourceId,
    cancellation: CancellationToken,
    *,
    minutes: int = 10,
    event_end: datetime | None = None,
    stdout_consumer: Callable[[bytes], None] | None = None,
) -> ProcessResult:
    if resource not in RESOURCES or type(minutes) is not int or not 1 <= minutes <= 60:
        raise ValueError("Invalid fixed collector request")
    if event_end is not None and (resource != "events" or event_end.utcoffset() != timedelta(0)):
        raise ValueError("Event window end must be a UTC timestamp for the fixed event resource")
    system = system_directory()
    executable = system / "WindowsPowerShell/v1.0/powershell.exe"
    check_plain_path(executable)
    if not executable.is_file():
        raise OSError("Windows PowerShell5.1 is unavailable")
    environment = {
        "SystemRoot": str(system.parent),
        "WINDIR": str(system.parent),
        "PATH": str(system),
        "PSModulePath": str(system / "WindowsPowerShell/v1.0/Modules"),
    }
    # Extract the trusted directory together so fixed local helpers remain colocated.
    with (
        as_file(files("wfdiag").joinpath("resources/powershell")) as directory,
        ExitStack() as held,
    ):
        opened = held.enter_context(closing(OpenedDirectory(directory)))
        script = directory / RESOURCES[resource]
        required = [script.name] + ([] if resource == "preflight" else ["Collection.Common.ps1"])
        for name in required:
            source = held.enter_context(opened.open_relative(name))
            content = source.read(65537)
            if (
                len(content) > 65536
                or hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()
                != RESOURCE_SHA256[name]
            ):
                raise ResourceIntegrityError("Fixed collector resource integrity failed")
        # Owner-approved process-only mode. No persistent policy mutation,
        # Bypass/Unrestricted, dynamic source or managed-policy override.
        argv = [
            str(executable),
            "-NoProfile",
            "-NonInteractive",
            *collector_policy_arguments(),
            "-File",
            str(script),
        ]
        if resource == "events":
            argv.extend(("-Minutes", str(minutes)))
            if event_end is not None:
                argv.extend(("-WindowEndUtc", event_end.isoformat(timespec="microseconds")))
        return _bounded_process(
            argv,
            cwd=executable.parent,
            cancellation=cancellation,
            timeout=120,
            output_limit={
                "preflight": 1024 * 1024,
                "host": 16 * 1024 * 1024,
                "policy": 256 * 1024 * 1024,
                "events": 128 * 1024 * 1024,
            }[resource],
            environment=environment,
            stdout_consumer=stdout_consumer,
        )


def current_device_mappings() -> dict[str, str]:
    """Current mappings are observations, not PID-based historical identity proof."""
    if sys.platform != "win32":
        return {}
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetLogicalDrives.argtypes = []
    api.GetLogicalDrives.restype = ctypes.c_uint32
    api.QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    api.QueryDosDeviceW.restype = ctypes.c_uint32
    drives = api.GetLogicalDrives()
    mappings: dict[str, str] = {}
    ambiguous: set[str] = set()
    for offset in range(26):
        if not drives & (1 << offset):
            continue
        drive = chr(ord("A") + offset) + ":"
        buffer = ctypes.create_unicode_buffer(32768)
        length = api.QueryDosDeviceW(drive, buffer, len(buffer))
        # Only the first string is current; subsequent strings are prior mappings.
        if (
            not length
            or length >= len(buffer)
            or not buffer.value.casefold().startswith("\\device\\")
        ):
            continue
        device = buffer.value.casefold()
        if device in mappings:
            ambiguous.add(device)
        else:
            mappings[device] = drive
    return {device: drive for device, drive in mappings.items() if device not in ambiguous}
