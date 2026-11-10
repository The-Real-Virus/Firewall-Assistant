"""Create a new directory with a protected inheritable operator/Admins/System DACL.

No existing ACL is modified. Native acceptance requires the approved Windows lab.
"""

import ctypes
import re
from ctypes import wintypes
from pathlib import Path

from wfdiag.storage.windows_files import WindowsDirectory


class SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("descriptor", ctypes.c_void_p),
        ("inherit_handle", wintypes.BOOL),
    ]


class AclHeader(ctypes.Structure):
    _fields_ = [
        ("revision", ctypes.c_ubyte),
        ("reserved", ctypes.c_ubyte),
        ("size", wintypes.WORD),
        ("count", wintypes.WORD),
        ("reserved2", wintypes.WORD),
    ]


class AllowedAce(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("size", wintypes.WORD),
        ("mask", wintypes.DWORD),
        ("sid_start", wintypes.DWORD),
    ]


def directory_sddl(operator_sid: str) -> str:
    if not re.fullmatch(r"S-1-[0-9]{1,15}-(?:[0-9]{1,10}-){0,14}[0-9]{1,10}", operator_sid):
        raise ValueError("Invalid operator SID")
    principals = tuple(dict.fromkeys((operator_sid, "S-1-5-32-544", "S-1-5-18")))
    return "O:" + operator_sid + "D:P" + "".join(f"(A;OICI;FA;;;{p})" for p in principals)


class WindowsPrivacy:
    def __init__(self) -> None:
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)
        k, a = self.kernel, self.security
        k.GetCurrentProcess.restype = wintypes.HANDLE
        k.GetCurrentThread.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        k.LocalFree.argtypes = [ctypes.c_void_p]
        k.LocalFree.restype = ctypes.c_void_p
        k.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
        k.CreateDirectoryW.restype = wintypes.BOOL
        a.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        a.OpenProcessToken.restype = wintypes.BOOL
        a.OpenThreadToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.BOOL,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        a.OpenThreadToken.restype = wintypes.BOOL
        a.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        a.GetTokenInformation.restype = wintypes.BOOL
        a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        a.ConvertSidToStringSidW.restype = wintypes.BOOL
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        a.GetSecurityInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        a.GetSecurityInfo.restype = wintypes.DWORD
        a.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        a.GetSecurityDescriptorControl.restype = wintypes.BOOL
        a.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        a.GetAce.restype = wintypes.BOOL

    def _sid(self, pointer: int | None) -> str:
        if pointer is None:
            raise PermissionError("Security principal is missing")
        output = wintypes.LPWSTR()
        if not self.security.ConvertSidToStringSidW(pointer, ctypes.byref(output)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return output.value or ""
        finally:
            self.kernel.LocalFree(output)

    def _operator_sid(self) -> str:
        token = wintypes.HANDLE()
        # This desktop application has no impersonation feature. Refuse an unexpected token.
        if self.security.OpenThreadToken(
            self.kernel.GetCurrentThread(), 8, True, ctypes.byref(token)
        ):
            self.kernel.CloseHandle(token)
            raise PermissionError("Impersonated output creation is unsupported")
        if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.security.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            needed = wintypes.DWORD()
            self.security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            if not 0 < needed.value <= 65536:
                raise PermissionError("Operator token could not be bounded")
            buffer = ctypes.create_string_buffer(needed.value)
            if not self.security.GetTokenInformation(
                token, 1, buffer, len(buffer), ctypes.byref(needed)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            return self._sid(ctypes.c_void_p.from_buffer(buffer).value)
        finally:
            self.kernel.CloseHandle(token)

    def _verify(self, directory: WindowsDirectory, operator: str) -> None:
        owner, acl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        status = self.security.GetSecurityInfo(
            directory.native_handle,
            1,
            5,
            ctypes.byref(owner),
            None,
            ctypes.byref(acl),
            None,
            ctypes.byref(descriptor),
        )
        if status:
            raise ctypes.WinError(status)
        try:
            control, revision = wintypes.WORD(), wintypes.DWORD()
            if not self.security.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if self._sid(owner.value) != operator or not control.value & 0x1000 or not acl.value:
                raise PermissionError("Output owner or protected DACL could not be verified")
            header = AclHeader.from_address(acl.value)
            expected = {operator, "S-1-5-32-544", "S-1-5-18"}
            if header.count != len(expected):
                raise PermissionError("Output DACL has unexpected entries")
            actual: set[str] = set()
            for index in range(header.count):
                pointer = ctypes.c_void_p()
                if not self.security.GetAce(acl, index, ctypes.byref(pointer)) or not pointer.value:
                    raise PermissionError("Output DACL entry could not be inspected")
                ace = AllowedAce.from_address(pointer.value)
                if ace.type != 0 or ace.flags != 3 or ace.mask != 0x001F01FF or ace.size < 20:
                    raise PermissionError("Output DACL permissions are unexpected")
                actual.add(self._sid(pointer.value + AllowedAce.sid_start.offset))
            if actual != expected:
                raise PermissionError("Output DACL principals are unexpected")
        finally:
            if descriptor.value:
                self.kernel.LocalFree(descriptor)

    def owner_sid(self, directory: WindowsDirectory) -> str:
        """Read an existing directory owner, without changing any security descriptor."""
        owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        status = self.security.GetSecurityInfo(
            directory.native_handle,
            1,
            1,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if status:
            raise ctypes.WinError(status)
        try:
            return self._sid(owner.value)
        finally:
            if descriptor.value:
                self.kernel.LocalFree(descriptor)

    def verify_permission_output(self, path: Path) -> WindowsDirectory:
        """Fixed collector may write a fresh caller-owned slot after Windows consent.

        Both directories must retain the same exact protected operator/Admins/System
        DACL. This supports a standard user entering another administrator's credentials
        without changing ownership, granting rights or weakening ordinary output checks.
        """
        parent = WindowsDirectory(path.parent, allow_child_writes=True)
        directory = None
        try:
            directory = WindowsDirectory(path, allow_child_writes=True)
            operator = self.owner_sid(parent)
            self._verify(parent, operator)
            self._verify(directory, operator)
            if any(path.iterdir()):
                raise FileExistsError("Permission collection slot is not empty")
            return directory
        except BaseException:
            if directory is not None:
                directory.close()
            raise
        finally:
            parent.close()

    def create(self, path: Path) -> WindowsDirectory:
        # Check locality and hold the existing plain parent before any creation.
        parent = WindowsDirectory(path.parent, allow_child_writes=True)
        try:
            operator = self._operator_sid()
            descriptor = ctypes.c_void_p()
            if not self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                directory_sddl(operator), 1, ctypes.byref(descriptor), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                attributes = SecurityAttributes(
                    ctypes.sizeof(SecurityAttributes), descriptor, False
                )
                if not self.kernel.CreateDirectoryW(
                    "\\\\?\\" + str(path), ctypes.byref(attributes)
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                self.kernel.LocalFree(descriptor)
            directory = WindowsDirectory(path, allow_child_writes=True)
            try:
                self._verify(directory, operator)
                return directory
            except BaseException:
                directory.close()
                # Keep an unverified empty directory for operator review; never broaden its ACL.
                raise
        finally:
            parent.close()

    def verify_existing(self, path: Path) -> WindowsDirectory:
        operator = self._operator_sid()
        directory = WindowsDirectory(path, allow_child_writes=True)
        try:
            self._verify(directory, operator)
            return directory
        except BaseException:
            directory.close()
            raise
