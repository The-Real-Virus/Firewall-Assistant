"""Permission boundary doubles; never approve a real Windows consent prompt in tests."""

import ctypes
import subprocess
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from wfdiag.gui import elevation
from wfdiag.services.permission_collection import PermissionCancellation, permission_collect
from wfdiag.storage.opened_files import OpenedDirectory


@pytest.mark.parametrize(
    "name,minutes",
    [("case", 1), ("permission-case-" + "a" * 36, True), ("permission-case-" + "a" * 36, 61)],
)
def test_permission_service_refuses_wrong_scope_before_collect(tmp_path, name, minutes):
    with pytest.raises(ValueError):
        permission_collect(tmp_path / name, minutes)


def test_permission_cancellation_only_observes_derived_flag(tmp_path):
    with closing(OpenedDirectory(tmp_path)) as parent:
        token = PermissionCancellation(parent, "case.cancel")
        assert not token.requested
        (tmp_path / "case.cancel").write_bytes(b"cancel")
        assert token.requested


def configure(monkeypatch, tmp_path, approve=True):
    seen = []
    monkeypatch.setattr(elevation.sys, "platform", "win32")
    monkeypatch.setattr(elevation.sys, "frozen", True, raising=False)
    monkeypatch.setattr(elevation.sys, "executable", str(tmp_path / "FirewallAssistant.exe"))
    checked = []
    monkeypatch.setattr(elevation, "verify_frozen_installation", lambda: checked.append(True))

    def launch(pointer):
        info = ctypes.cast(pointer, ctypes.POINTER(elevation.ShellExecuteInfo)).contents
        seen.append((info.lpFile, info.lpParameters, info.lpVerb, info.nShow))
        info.hProcess = 123 if approve else None
        return approve

    def exit_code(handle, pointer):
        ctypes.cast(pointer, ctypes.POINTER(elevation.wintypes.DWORD)).contents.value = 0
        return True

    shell = SimpleNamespace(ShellExecuteExW=Mock(side_effect=launch))
    kernel = SimpleNamespace(
        GetExitCodeProcess=Mock(side_effect=exit_code), CloseHandle=Mock(return_value=True)
    )
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, **kwargs: shell if name == "shell32" else kernel
    )
    return seen, checked, kernel


def test_permission_launches_only_verified_sibling_with_fixed_collect_arguments(
    tmp_path, monkeypatch
):
    seen, checked, kernel = configure(monkeypatch, tmp_path)
    out = tmp_path / "Output with spaces Ω" / "permission-case-01234567-89ab-cdef-0123-456789abcdef"
    process = elevation.request_collection(out, 17, 0)
    file, args, verb, shown = seen[0]
    assert file == str(tmp_path / "wfdiag.exe")
    assert args == subprocess.list2cmdline(
        ["permission-collect", "--minutes", "17", "--out", str(out)]
    )
    assert checked == [True] and verb == "runas" and shown == 0
    assert process.poll() == 0
    process.close()
    process.close()
    kernel.CloseHandle.assert_called_once()


def test_permission_decline_never_returns_a_process_or_reports_success(tmp_path, monkeypatch):
    seen, _, kernel = configure(monkeypatch, tmp_path, False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1223)
    with pytest.raises(elevation.PermissionDeclined):
        elevation.request_collection(
            tmp_path / "permission-case-01234567-89ab-cdef-0123-456789abcdef", 1, 0
        )
    assert len(seen) == 1
    kernel.GetExitCodeProcess.assert_not_called()
