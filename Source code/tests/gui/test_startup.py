"""Startup order and fallback with explicit Qt/storage/instance-lock doubles."""

import pytest
from PySide6 import QtCore, QtGui, QtWidgets

from wfdiag.gui import app, controller, main_window, preferences, theme
from wfdiag.gui.preferences import Preferences
from wfdiag.storage import private_output


@pytest.fixture
def startup(tmp_path, monkeypatch):
    events = []
    root = tmp_path / "invented-private-app-data"
    root.mkdir()
    options = {"locked": False, "corrupt": False, "denied": False}
    original_application = QtWidgets.QApplication

    class Application:
        def __init__(self, *args):
            pass

        instance = staticmethod(original_application.instance)

        def setApplicationName(self, value):
            pass

        def setOrganizationName(self, value):
            pass

        def setStyle(self, value):
            pass

        def setFont(self, value):
            pass

        def exec(self):
            events.append("event-loop")
            return 0

    class Held:
        def close(self):
            events.append("held-close")

    class Lock:
        def __init__(self, path):
            assert str(root) in path
            events.append("lock-created")

        def setStaleLockTime(self, value):
            assert value == 0

        def tryLock(self, timeout):
            assert timeout == 0
            events.append("try-lock")
            return not options["locked"]

        def unlock(self):
            events.append("unlock")

    class Window:
        def __init__(self, prefs, store):
            events.append(("window", prefs))
            assert isinstance(prefs, Preferences)

        def show(self):
            events.append("show")

        def statusBar(self):
            return self

        def showMessage(self, text):
            events.append(("warning", text))

    def prepare(path):
        assert path == root
        events.append("prepare-private-root")
        if options["denied"]:
            raise PermissionError("CANARY_RAW_EXCEPTION")
        return root

    def load(self):
        events.append("load-preferences")
        if options["corrupt"]:
            raise ValueError("CANARY_RAW_KEY_RECORD")
        return Preferences(theme="Dark")

    monkeypatch.setattr(QtWidgets, "QApplication", Application)
    monkeypatch.setattr(QtCore, "QLockFile", Lock)
    monkeypatch.setattr(QtGui, "QFont", lambda *args: None)
    monkeypatch.setattr(
        QtWidgets.QMessageBox, "information", lambda *args: events.append("already-open")
    )
    monkeypatch.setattr(
        QtWidgets.QMessageBox, "critical", lambda *args: events.append(("storage-error", args[-1]))
    )
    monkeypatch.setattr(controller, "default_work_root", lambda: root)
    monkeypatch.setattr(controller, "prepare_work_root", prepare)
    monkeypatch.setattr(private_output, "verify_private_directory", lambda root: Held())
    monkeypatch.setattr(preferences.PreferenceStore, "load", load)
    monkeypatch.setattr(main_window, "MainWindow", Window)
    monkeypatch.setattr(theme, "apply_theme", lambda *args: None)
    return options, events


def test_startup_locks_before_loading_preferences_or_opening_window(startup) -> None:
    _, events = startup
    assert app.main() == 0
    assert events.index("try-lock") < events.index("load-preferences")
    assert events[-2:] == ["unlock", "held-close"]
    prefs = next(row[1] for row in events if isinstance(row, tuple) and row[0] == "window")
    assert prefs.theme == "Dark" and not prefs.history_enabled and not prefs.recent


def test_corrupt_settings_open_safe_default_gui_without_echoing_raw_data(startup) -> None:
    options, events = startup
    options["corrupt"] = True
    assert app.main() == 0
    prefs = next(row[1] for row in events if isinstance(row, tuple) and row[0] == "window")
    assert prefs == Preferences()
    assert "CANARY" not in str(events)
    assert any(isinstance(row, tuple) and row[0] == "warning" for row in events)


def test_second_instance_stops_before_settings_or_diagnostic_work(startup) -> None:
    options, events = startup
    options["locked"] = True
    assert app.main() == 2
    assert "already-open" in events and "load-preferences" not in events
    assert not any(isinstance(row, tuple) and row[0] == "window" for row in events)


def test_unverifiable_private_startup_storage_fails_closed_without_collection(startup) -> None:
    options, events = startup
    options["denied"] = True
    assert app.main() == 4
    assert "load-preferences" not in events and "try-lock" not in events
    assert "CANARY" not in str(events)


def test_early_qt_import_failure_is_reported_without_raw_exception(monkeypatch, capsys) -> None:
    import builtins

    original = builtins.__import__

    def importing(name, *args, **kwargs):
        if name == "PySide6.QtCore":
            raise ImportError("CANARY_NATIVE_LOAD_PATH")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
    assert app.main() == 3
    output = capsys.readouterr().err
    assert "GUI_IMPORT_FAILED" in output and "CANARY" not in output
