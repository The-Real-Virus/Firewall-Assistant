"""Own a suspended Windows child before it can create descendants.

Only used for processes created by this application. No global process-name termination.
Windows imports/calls are delayed until this boundary is invoked.
"""

from __future__ import annotations

import ctypes
import subprocess
import time
from ctypes import wintypes


class BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong),
        ("job_time", ctypes.c_longlong),
        ("flags", wintypes.DWORD),
        ("minimum_working_set", ctypes.c_size_t),
        ("maximum_working_set", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "read_operations",
            "write_operations",
            "other_operations",
            "read_bytes",
            "write_bytes",
            "other_bytes",
        )
    ]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", BasicLimits),
        ("io", IoCounters),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t),
        ("peak_job_memory", ctypes.c_size_t),
    ]


class ThreadEntry(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("usage", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
        ("owner_pid", wintypes.DWORD),
        ("base_priority", wintypes.LONG),
        ("delta_priority", wintypes.LONG),
        ("flags", wintypes.DWORD),
    ]


class ProcessIdList(ctypes.Structure):
    _fields_ = [
        ("assigned", wintypes.DWORD),
        ("count", wintypes.DWORD),
        ("pids", ctypes.c_size_t * 64),
    ]


class WindowsJob:
    def __init__(self) -> None:
        self._api = ctypes.WinDLL("kernel32", use_last_error=True)
        api = self._api
        api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        api.CreateJobObjectW.restype = wintypes.HANDLE
        api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        api.SetInformationJobObject.restype = wintypes.BOOL
        api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        api.AssignProcessToJobObject.restype = wintypes.BOOL
        api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenProcess.restype = wintypes.HANDLE
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        api.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        api.Thread32First.restype = wintypes.BOOL
        api.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        api.Thread32Next.restype = wintypes.BOOL
        api.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenThread.restype = wintypes.HANDLE
        api.ResumeThread.argtypes = [wintypes.HANDLE]
        api.ResumeThread.restype = wintypes.DWORD
        api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        api.TerminateJobObject.restype = wintypes.BOOL
        api.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        api.QueryInformationJobObject.restype = wintypes.BOOL
        api.IsProcessInJob.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        ]
        api.IsProcessInJob.restype = wintypes.BOOL
        api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        api.WaitForSingleObject.restype = wintypes.DWORD
        self._handle: int | None = api.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000 | 0x8  # KILL_ON_JOB_CLOSE | ACTIVE_PROCESS; no breakaway.
        limits.basic.active_process_limit = 64
        if not api.SetInformationJobObject(
            self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)

    def assign_and_resume(self, process: subprocess.Popen[bytes]) -> None:
        handle = self._api.OpenProcess(0x0101, False, process.pid)  # SET_QUOTA | TERMINATE.
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self._api.AssignProcessToJobObject(self._handle, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self._api.CloseHandle(handle)
        snapshot = self._api.CreateToolhelp32Snapshot(0x4, 0)
        if snapshot in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        thread_ids: list[int] = []
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            present = self._api.Thread32First(snapshot, ctypes.byref(entry))
            examined = 0
            while present:
                examined += 1
                if examined > 100000:
                    raise OSError("Thread snapshot exceeded its bound")
                if entry.owner_pid == process.pid:
                    thread_ids.append(entry.thread_id)
                present = self._api.Thread32Next(snapshot, ctypes.byref(entry))
            if ctypes.get_last_error() not in (0, 18):  # ERROR_NO_MORE_FILES
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self._api.CloseHandle(snapshot)
        if len(thread_ids) != 1:
            raise OSError("Cannot identify the owned suspended primary thread")
        thread = self._api.OpenThread(0x2, False, thread_ids[0])  # SUSPEND_RESUME only.
        if not thread:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if self._api.ResumeThread(thread) != 1:
                raise OSError("Owned primary thread did not resume from its expected state")
        finally:
            self._api.CloseHandle(thread)

    def close(self) -> None:
        if self._handle is None:
            return
        handle = self._handle
        processes: dict[int, int] = {}
        deadline = time.monotonic() + 5
        try:
            self._retain_owned_processes(handle, processes)
            if not self._api.TerminateJobObject(handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            while True:
                # Capture any descendant that joined between the first snapshot and termination.
                active = self._retain_owned_processes(handle, processes)
                for process in processes.values():
                    remaining = max(0, int((deadline - time.monotonic()) * 1000))
                    result = self._api.WaitForSingleObject(process, remaining)
                    if result != 0:
                        raise OSError(
                            "Owned process termination was not confirmed within the cleanup bound"
                        )
                if active == 0:
                    break
                if time.monotonic() >= deadline:
                    raise OSError("Owned job did not empty within the cleanup bound")
                time.sleep(0.01)
        finally:
            for process in processes.values():
                self._api.CloseHandle(process)
            self._handle = None
            if not self._api.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())

    def _retain_owned_processes(self, job: int, retained: dict[int, int]) -> int:
        identifiers = ProcessIdList()
        if not self._api.QueryInformationJobObject(
            job, 3, ctypes.byref(identifiers), ctypes.sizeof(identifiers), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if (
            identifiers.assigned > 64
            or identifiers.count > 64
            or identifiers.count < identifiers.assigned
        ):
            raise OSError("Owned job process list exceeded its configured bound")
        for pid in identifiers.pids[: identifiers.count]:
            if pid in retained:
                continue
            process = self._api.OpenProcess(
                0x00101000, False, pid
            )  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION.
            if not process:
                if ctypes.get_last_error() == 87:  # The process already exited.
                    continue
                raise ctypes.WinError(ctypes.get_last_error())
            member = wintypes.BOOL()
            try:
                if not self._api.IsProcessInJob(process, job, ctypes.byref(member)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if member.value:
                    retained[pid] = process  # Retain object identity across PID reuse.
                    process = None
            finally:
                if process is not None:
                    self._api.CloseHandle(process)
        return int(identifiers.count)
