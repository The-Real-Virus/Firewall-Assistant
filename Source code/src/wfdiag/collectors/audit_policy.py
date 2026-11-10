"""Observe failure-audit policy via the read-only native API; never enable privileges."""

import ctypes
import sys
from ctypes import wintypes
from uuid import UUID


class Guid(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    ]


class AuditInformation(ctypes.Structure):
    _fields_ = [("subcategory", Guid), ("options", wintypes.ULONG), ("category", Guid)]


def failure_audit_codes() -> tuple[str, ...]:
    if sys.platform != "win32":
        return ("AUDIT_CONFIGURATION_NOT_ESTABLISHED",)
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.AuditQuerySystemPolicy.argtypes = [
        ctypes.POINTER(Guid),
        wintypes.ULONG,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    api.AuditQuerySystemPolicy.restype = ctypes.c_ubyte
    api.AuditFree.argtypes = [ctypes.c_void_p]
    api.AuditFree.restype = None
    identifiers = ("0cce9226-69ae-11d9-bed3-505054503030", "0cce9225-69ae-11d9-bed3-505054503030")
    guids = (Guid * 2)(*(Guid.from_buffer_copy(UUID(value).bytes_le) for value in identifiers))
    output = ctypes.c_void_p()
    if not api.AuditQuerySystemPolicy(guids, 2, ctypes.byref(output)):
        return ("AUDIT_CONFIGURATION_NOT_ESTABLISHED",)
    try:
        values = ctypes.cast(output, ctypes.POINTER(AuditInformation))
        codes = []
        for index, event in enumerate((5157, 5152)):
            if bytes(values[index].subcategory) != bytes(guids[index]):
                return ("AUDIT_CONFIGURATION_NOT_ESTABLISHED",)
            codes.append(
                f"AUDIT_{event}_FAILURE_" + ("ENABLED" if values[index].options & 2 else "DISABLED")
            )
        return tuple(codes)
    finally:
        api.AuditFree(output)
