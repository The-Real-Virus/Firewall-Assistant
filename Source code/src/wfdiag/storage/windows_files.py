"""Open local bundle children relative to a held directory, without following reparse points."""

import ctypes
import ntpath
import os
from ctypes import wintypes
from pathlib import Path
from typing import BinaryIO


class UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", wintypes.LPWSTR),
    ]


class ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root", wintypes.HANDLE),
        ("name", ctypes.POINTER(UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security_descriptor", ctypes.c_void_p),
        ("security_qos", ctypes.c_void_p),
    ]


class IoStatus(ctypes.Structure):
    _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]


class FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation", wintypes.FILETIME),
        ("access", wintypes.FILETIME),
        ("write", wintypes.FILETIME),
        ("volume", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


def _normal(value: str) -> str:
    value = value.removeprefix("\\\\?\\")
    return ntpath.normcase(ntpath.normpath(value))


class WindowsDirectory:
    def __init__(self, path: Path, *, allow_child_writes: bool = False) -> None:
        self.path = path
        self._api = ctypes.WinDLL("kernel32", use_last_error=True)
        self._nt = ctypes.WinDLL("ntdll", use_last_error=True)
        api = self._api
        api.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        api.GetDriveTypeW.restype = wintypes.UINT
        api.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        api.CreateFileW.restype = wintypes.HANDLE
        api.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
        api.GetFileInformationByHandle.restype = wintypes.BOOL
        api.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        api.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        self._nt.NtCreateFile.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            ctypes.POINTER(ObjectAttributes),
            ctypes.POINTER(IoStatus),
            ctypes.c_void_p,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
        ]
        self._nt.NtCreateFile.restype = wintypes.LONG
        self._nt.RtlNtStatusToDosError.argtypes = [wintypes.LONG]
        self._nt.RtlNtStatusToDosError.restype = wintypes.ULONG
        if api.GetDriveTypeW(path.drive + "\\") not in (2, 3, 5, 6):
            raise ValueError("Only local case storage is accepted")
        self._handle: int | None = api.CreateFileW(
            "\\\\?\\" + str(path),
            0x80000020,
            3 if allow_child_writes else 1,  # Share writes only on the directory; never delete.
            None,
            3,
            0x02000000 | 0x00200000,
            None,
        )
        if self._handle in (None, ctypes.c_void_p(-1).value):
            self._handle = None
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = self._information(self._handle)
            if not info.attributes & 0x10 or info.attributes & 0x400:
                raise ValueError("Selected case is not a plain directory")
            if _normal(self._final_path(self._handle)) != _normal(str(path)):
                raise ValueError("Selected directory resolved through an alias or redirection")
        except BaseException:
            self.close()
            raise

    def _information(self, handle: int) -> FileInformation:
        info = FileInformation()
        if not self._api.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return info

    def _final_path(self, handle: int) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        size = self._api.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not size or size >= len(buffer):
            raise OSError("Opened file path could not be validated")
        return buffer.value

    def open_relative(self, name: str) -> BinaryIO:
        if not name or name in (".", "..") or any(c in name for c in ("/", "\\", ":", "\x00")):
            raise ValueError("Invalid relative case filename")
        if self._handle is None:
            raise ValueError("Case directory is closed")
        import msvcrt

        buffer = ctypes.create_unicode_buffer(name)
        encoded = name.encode("utf-16-le")
        text = UnicodeString(len(encoded), len(encoded) + 2, ctypes.cast(buffer, wintypes.LPWSTR))
        attributes = ObjectAttributes(
            ctypes.sizeof(ObjectAttributes), self._handle, ctypes.pointer(text), 0x40, None, None
        )
        handle = wintypes.HANDLE()
        status_block = IoStatus()
        status = self._nt.NtCreateFile(
            ctypes.byref(handle),
            0x00120089,  # FILE_GENERIC_READ includes the SYNCHRONIZE right required below.
            ctypes.byref(attributes),
            ctypes.byref(status_block),
            None,
            0,
            1,
            1,
            0x00200000 | 0x40 | 0x20 | 0x4,
            None,
            0,
        )
        if status < 0:
            raise ctypes.WinError(self._nt.RtlNtStatusToDosError(status))
        native_handle = handle.value
        if native_handle is None:
            raise OSError("Opened source handle is missing")
        transferred = False
        try:
            info = self._information(native_handle)
            if info.attributes & (0x400 | 0x10) or info.links != 1:
                raise ValueError("Case source must be a plain, singly linked file")
            if _normal(ntpath.dirname(self._final_path(native_handle))) != _normal(
                self._final_path(self._handle)
            ):
                raise ValueError("Opened source is outside the held case directory")
            descriptor = msvcrt.open_osfhandle(
                native_handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT
            )
            transferred = True
            try:
                return os.fdopen(descriptor, "rb", buffering=65536)
            except BaseException:
                os.close(descriptor)
                raise
        finally:
            if not transferred:
                self._api.CloseHandle(handle)

    @property
    def native_handle(self) -> int:
        if self._handle is None:
            raise ValueError("Case directory is closed")
        return self._handle

    def close(self) -> None:
        if self._handle is not None:
            handle, self._handle = self._handle, None
            if not self._api.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())
