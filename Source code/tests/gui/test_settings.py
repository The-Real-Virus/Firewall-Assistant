"""Settings UI with an explicit in-memory store; no native privacy acceptance."""

from importlib.resources import files

from PySide6.QtWidgets import QApplication, QDialog, QInputDialog, QPlainTextEdit

from wfdiag.contracts.models import Analysis
from wfdiag.gui import settings as module
from wfdiag.gui.main_window import MainWindow
from wfdiag.gui.preferences import Preferences, PreferenceStore


class MemoryStore(PreferenceStore):
    def __init__(self):
        self.saved = []

    def save(self, preferences):
        self.saved.append(preferences)


def test_theme_history_and_motion_persist_without_keys_or_automatic_paths(qtbot) -> None:
    store = MemoryStore()
    window = MainWindow(Preferences(), store)
    qtbot.addWidget(window)
    window.show()
    window.set_theme("Dark")
    window.settings_view.motion.setChecked(True)
    qtbot.waitUntil(lambda: bool(store.saved))
    assert store.saved[-1].theme == "Dark" and store.saved[-1].reduced_motion
    assert QApplication.instance().property("reduceMotion")
    assert not store.saved[-1].recent and not store.saved[-1].history_enabled
    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    assert not window.preferences.value.recent
    assert "api_key" not in window.preferences.value.model_dump_json()
    window.close()
    qtbot.waitUntil(lambda: not window.isVisible())


def test_named_history_reopens_by_revalidation_api_and_clear_keeps_evidence(
    qtbot, tmp_path, monkeypatch
) -> None:
    store = MemoryStore()
    window = MainWindow(Preferences(history_enabled=True), store)
    qtbot.addWidget(window)
    window.show()
    path = tmp_path / "synthetic-existing-case"
    path.mkdir()
    (path / "keep.txt").write_text("invented evidence")
    analysis = Analysis.model_validate_json(
        files("wfdiag").joinpath("gui/resources/synthetic-analysis.json").read_bytes()
    )
    window.controller.bind(analysis, path)
    assert window.preferences.value.recent == ()
    monkeypatch.setattr(QInputDialog, "getText", lambda *args: ("Operator-selected label", True))
    window.settings_view.remember_case()
    assert window.settings_view.recent.item(0).text() == "Operator-selected label"
    assert window.preferences.value.recent[0].path == str(path)
    opened = []
    monkeypatch.setattr(window.controller, "open_analysis", lambda value: opened.append(value))
    window.settings_view.recent.setCurrentRow(0)
    window.settings_view.reopen()
    assert opened == [path]
    window.settings_view.history.setChecked(False)
    assert window.preferences.value.recent == ()
    assert (path / "keep.txt").read_text() == "invented evidence"
    window.close()
    qtbot.waitUntil(lambda: not window.isVisible())


def test_new_work_location_does_not_move_or_delete_existing_files(
    qtbot, tmp_path, monkeypatch
) -> None:
    from wfdiag.gui import controller

    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    previous = tmp_path / "old-case"
    previous.mkdir()
    (previous / "keep.txt").write_text("invented")
    window.controller.root = previous
    monkeypatch.setattr(module.QFileDialog, "getExistingDirectory", lambda *args: str(tmp_path))

    def prepare(root):
        root.mkdir()
        return root

    monkeypatch.setattr(controller, "prepare_work_root", prepare)  # Explicit native privacy double.
    window.settings_view.choose_work_root()
    qtbot.waitUntil(lambda: not window.controller.busy)
    new_root = window.controller.root
    assert new_root != previous and new_root.is_dir()
    assert window.preferences.value.work_root == str(new_root)
    assert window.job_status.text() == "Private work folder ready."
    assert (previous / "keep.txt").read_text() == "invented"
    window.close()


def test_export_suggests_unique_names_in_prepared_work_folder(qtbot, tmp_path, monkeypatch):
    from wfdiag.gui import controller

    window = MainWindow()
    qtbot.addWidget(window)
    root = tmp_path / "private-work"
    window.controller.root = root
    prepared = []
    suggestions = []

    def prepare(path):
        prepared.append(path)
        return path

    def cancel_dialog(_parent, _title, suggestion, _filter):
        suggestions.append(suggestion)
        return "", ""

    monkeypatch.setattr(controller, "prepare_work_root", prepare)
    monkeypatch.setattr(controller.QFileDialog, "getSaveFileName", cancel_dialog)
    window.controller.message("Previous result")
    selected = []
    for count in (1, 2):
        window.controller.choose_output("Export", "share.html", "Reports", selected.append)
        qtbot.waitUntil(lambda count=count: len(suggestions) == count)

    assert prepared == [root, root]
    assert len(set(suggestions)) == 2
    assert all(value.startswith(str(root / "share-")) for value in suggestions)
    assert all(value.endswith(".html") for value in suggestions)
    assert not selected
    assert window.job_status.text() == "Previous result"
    window.close()


def test_local_help_is_plain_text_and_has_no_cloud_or_firewall_action(qtbot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window.settings_view.help()
    dialog = window.findChild(QDialog)
    assert dialog is not None
    view = dialog.findChild(QPlainTextEdit)
    assert view.isReadOnly() and "Full diagnostics work without AI" in view.toPlainText()
    assert "not a signed approved release" in view.toPlainText()
    assert window.ai_destination.view is None and window.controller.jobs is None
    dialog.close()
    window.close()
