"""Early failures remain visible without importing Qt or revealing exceptions."""

import sys
from types import ModuleType

import pytest

from wfdiag.gui import launcher


def test_unexpected_startup_exception_has_fixed_message(monkeypatch, capsys) -> None:
    desktop = ModuleType("wfdiag.gui.app")

    def failed(**kwargs):
        raise RuntimeError("CANARY_PRIVATE_CASE_OR_KEY")

    desktop.main = failed
    monkeypatch.setitem(sys.modules, "wfdiag.gui.app", desktop)
    monkeypatch.setattr(sys, "argv", ["FirewallAssistant.exe"])
    assert launcher.main() == 5
    output = capsys.readouterr().err
    assert "GUI_STARTUP_FAILED" in output and "CANARY" not in output


def test_no_console_failure_uses_native_message_without_qt(monkeypatch) -> None:
    import ctypes

    calls = []

    class Message:
        def __call__(self, *args):
            calls.append(args)
            return 1

    class Native:
        MessageBoxW = Message()

    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: Native(), raising=False)
    launcher.startup_error("GUI_IMPORT_FAILED")
    assert len(calls) == 1 and "GUI_IMPORT_FAILED" in calls[0][1]
    assert calls[0][-1] == 0x10


@pytest.mark.parametrize("args", [["--unknown"], ["--startup-check", "relative"]])
def test_invalid_check_arguments_refused_without_qt(monkeypatch, args, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["FirewallAssistant.exe", *args])
    assert launcher.main() == 2
    assert "GUI_ARGUMENTS_INVALID" in capsys.readouterr().err


def test_check_never_reuses_existing_directory(monkeypatch, tmp_path, capsys) -> None:
    marker = tmp_path / "keep.txt"
    marker.write_text("owner data", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["FirewallAssistant.exe", "--startup-check", str(tmp_path)])
    assert launcher.main() == 2
    assert marker.read_text("utf-8") == "owner data"
    assert list(tmp_path.iterdir()) == [marker]
    assert "GUI_ARGUMENTS_INVALID" in capsys.readouterr().err
