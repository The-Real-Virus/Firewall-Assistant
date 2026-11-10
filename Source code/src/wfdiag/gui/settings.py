"""Private preferences/history and local help; no cloud or firewall controls."""

from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from wfdiag.gui.preferences import Preferences, PreferenceStore, RecentCase
from wfdiag.version import DISPLAY_VERSION

if TYPE_CHECKING:
    from wfdiag.gui.main_window import MainWindow


class SavePreferences(QRunnable):
    def __init__(self, owner: "PreferenceManager", snapshot: Preferences, generation: int) -> None:
        super().__init__()
        self.owner, self.snapshot, self.generation = owner, snapshot, generation

    def run(self) -> None:
        code = ""
        try:
            if self.owner.store is None:
                raise OSError("Private preferences unavailable")
            self.owner.store.save(self.snapshot)
        except Exception:  # noqa: BLE001 -- do not emit paths or raw storage exceptions.
            code = "PRIVATE_PREFERENCES_UNAVAILABLE"
        self.owner.completed.emit(self.generation, code)


class PreferenceManager(QObject):
    changed = Signal()
    status = Signal(str)
    completed = Signal(int, str)

    def __init__(self, parent: QObject, value: Preferences, store: PreferenceStore | None) -> None:
        super().__init__(parent)
        self.value, self.store = value, store
        self.dirty = False
        self.busy = False
        self.generation = 0
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(300)
        self.timer.timeout.connect(self.flush)
        self.completed.connect(self.finished, Qt.ConnectionType.QueuedConnection)

    def update(self, value: Preferences) -> None:
        self.value = value
        self.generation += 1
        self.dirty = True
        self.changed.emit()
        self.timer.start()

    def flush(self) -> bool:
        self.timer.stop()
        if self.busy:
            return False
        if not self.dirty:
            return True
        if self.store is None:
            self.dirty = False
            self.status.emit(
                "Preferences are session-only because private settings storage is unavailable. No fallback file was written."
            )
            return True
        self.busy = True
        self.pool.start(SavePreferences(self, self.value, self.generation))
        return False

    def finished(self, generation: int, code: str) -> None:
        self.busy = False
        if generation == self.generation:
            self.dirty = False
        self.status.emit(
            "Private preferences saved. History never deletes evidence."
            if not code
            else "PRIVATE_PREFERENCES_UNAVAILABLE · Session choices remain active; no fallback file was written."
        )
        if self.dirty:
            self.flush()


def text(value: str, name: str = "") -> QLabel:
    result = QLabel(value)
    result.setTextFormat(Qt.TextFormat.PlainText)
    result.setWordWrap(True)
    if name:
        result.setObjectName(name)
    return result


HELP = """Using Firewall Assistant

The GUI and wfdiag administrator CLI share one diagnostic engine. Full diagnostics work without AI, an API key or internet. Protection stays enabled; the application never applies firewall changes or launches a target application.

1. Open the bundled synthetic example to learn the findings/evidence/proposal/export views without inspecting this computer.
2. In an authorized test environment, run preflight and deliberately collect existing local evidence, or open an existing validated case. Missing access and incomplete sources remain visible.
3. General analysis requires no intended flow. A specific TCP intent requires an independently verified executable, direction, profile, approved peer scope, service port and purpose. Outbound client service ports are remote; inbound service ports are local. An ephemeral client port is not an intended service port.
4. Review category, evidence grade, relevance and completeness separately. Missing events do not prove the host is secure. Unsupported or unknown conditions remain unknown. Changed intent requires reanalysis before proposals.
5. Reveal local details only deliberately. Share exports use a separate allowlisted derivative; review it before sharing. Full reports contain sensitive local data. Existing output destinations are never silently overwritten.
6. Proposals are review-only nonexecuting JSON. Explicit blocks and managed policy require the responsible policy owner; an additional allow exception does not override an explicit block in this scope.
7. Compare Before and After analyses to review captured changes and limitations. Fewer blocks or no relevant events do not establish repair.

History is off by default. Enabling it permits explicitly named recent entries, at most20. Reopening revalidates the actual files. Clear history removes only the index. Changing work location does not migrate or delete earlier cases, jobs or exports.

Optional AI is off by default. Enable AI, choose your provider, paste a key in the masked field and choose Connect & test. Then chat naturally or request app tasks: check access, collect/analyze evidence, open cases, explain findings, export reports and compare cases. It uses the same application services and current Windows permissions. It cannot change engine findings or Windows/firewall settings, run arbitrary commands or upload raw cases. Your messages and redacted summaries go to the provider with up to5 recent exchanges; provider terms and charges apply. Session-only keys are the default. Disable or New chat clears conversation memory; remembered Windows credentials require Forget. Details shows the last redacted request and request count.

Cancellation and interruptions do not establish completion. Incomplete staging remains excluded. Keep original evidence and independently review conclusions. Native compatibility, privacy, accessibility, live API and release validation are unfinished in this local evaluation build.

Signing verification

This local development candidate is not a signed approved release. A checksum detects byte changes but does not authenticate a publisher. For a future signed release, use Windows file Properties / Digital Signatures and verify the expected publisher, certificate chain and timestamp against the approved release record. No signing certificate or private key is included.
"""


class SettingsView(QScrollArea):
    def __init__(self, window: "MainWindow") -> None:
        super().__init__()
        self.host_window = window
        self.manager = window.preferences
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content.setObjectName("page")
        self.setWidget(content)
        body = QVBoxLayout(content)
        body.setContentsMargins(32, 28, 32, 24)
        body.setSpacing(16)
        body.addWidget(text("Settings", "title"))
        body.addWidget(text("Private workspace choices; no firewall or cloud controls.", "muted"))
        body.addWidget(text("Appearance", "section"))
        self.theme = QComboBox()
        self.theme.addItems(["System", "Light", "Dark", "High contrast"])
        self.theme.setAccessibleName("Appearance theme")
        self.theme.setCurrentText(self.manager.value.theme)
        self.theme.currentTextChanged.connect(window.set_theme)
        body.addWidget(self.theme)
        self.motion = QCheckBox("Reduce motion")
        self.motion.setChecked(self.manager.value.reduced_motion)
        self.motion.toggled.connect(lambda checked: self.change(reduced_motion=checked))
        body.addWidget(self.motion)
        body.addWidget(text("Recent cases", "section"))
        self.history = QCheckBox("Remember recent cases")
        self.history.setChecked(self.manager.value.history_enabled)
        self.history.toggled.connect(self.history_changed)
        body.addWidget(self.history)
        body.addWidget(
            text(
                "History is off by default. Add only operator-named entries; at most20 are retained privately. Reopening always revalidates the actual evidence. Clearing or removing an entry never deletes a case, job or export.",
                "muted",
            )
        )
        self.recent = QListWidget()
        self.recent.setAccessibleName("Private recent case names")
        self.recent.setMaximumHeight(160)
        body.addWidget(self.recent)
        controls = QHBoxLayout()
        self.add = QPushButton("Add current case")
        self.open = QPushButton("Reopen selected")
        self.remove = QPushButton("Remove entry")
        self.clear = QPushButton("Clear history")
        for item in (self.add, self.open, self.remove, self.clear):
            controls.addWidget(item)
        body.addLayout(controls)
        self.add.clicked.connect(self.remember_case)
        self.open.clicked.connect(self.reopen)
        self.remove.clicked.connect(self.remove_entry)
        self.clear.clicked.connect(lambda: self.change(recent=[]))
        body.addWidget(text("Private work location", "section"))
        window.work_location_label = text(
            self.manager.value.work_root
            or "Per-user local application data; no migration or automatic evidence cleanup"
        )
        body.addWidget(window.work_location_label)
        choose = QPushButton("Choose parent for a new private work folder")
        choose.clicked.connect(self.choose_work_root)
        body.addWidget(choose)
        body.addWidget(
            text(
                "Existing jobs, cases and exports stay in their original locations. Private permissions are verified before use. No owner-selected folder is silently modified or deleted.",
                "muted",
            )
        )
        body.addWidget(text(f"Firewall Assistant {DISPLAY_VERSION}", "section"))
        help_button = QPushButton("Open local help, notices and signing guidance")
        help_button.clicked.connect(self.help)
        body.addWidget(help_button)
        clear_logs = QPushButton("Clear diagnostic log buffer")
        clear_logs.setAccessibleName("Clear in-memory diagnostic technical log buffer")
        clear_logs.clicked.connect(self.clear_logs)
        body.addWidget(clear_logs)
        body.addWidget(
            text(
                "Technical stderr is held in memory only, at most1MiB for the current or last job. Clear removes that buffer. Cases, exports, job requests and history are kept; no selected folder is deleted.",
                "muted",
            )
        )
        self.save_status = text(
            "Private preferences are saved after deliberate changes. No API keys or conversations are stored here.",
            "muted",
        )
        body.addWidget(self.save_status)
        self.manager.status.connect(self.save_status.setText)
        self.manager.changed.connect(self.refresh)
        body.addStretch()
        self.refresh()

    def change(self, **values: object) -> None:
        self.manager.update(self.manager.value.changed(**values))

    def clear_logs(self) -> None:
        controller = self.host_window.controller
        if controller.busy or (controller.jobs is not None and controller.jobs.busy):
            self.save_status.setText(
                "Wait for the current diagnostic operation before clearing its log buffer."
            )
            return
        if controller.jobs is not None:
            controller.jobs.clear_log_buffer()
        self.save_status.setText(
            "Diagnostic log buffer cleared. Cases, exports, job metadata and history are retained."
        )

    def history_changed(self, enabled: bool) -> None:
        self.change(
            history_enabled=enabled,
            recent=[item.model_dump(mode="json") for item in self.manager.value.recent]
            if enabled
            else [],
        )

    def refresh(self) -> None:
        self.recent.clear()
        for item in self.manager.value.recent:
            self.recent.addItem(item.name)
        self.add.setEnabled(self.manager.value.history_enabled)
        self.theme.blockSignals(True)
        self.theme.setCurrentText(self.manager.value.theme)
        self.theme.blockSignals(False)
        app = QApplication.instance()
        if app is not None:
            app.setProperty("reduceMotion", self.manager.value.reduced_motion)

    def remember_case(self) -> None:
        case = self.host_window.case_view
        if case.analysis is None or case.path is None or case.synthetic:
            self.save_status.setText(
                "Open a validated saved analysis before adding history. The bundled example is not evidence."
            )
            return
        name, accepted = QInputDialog.getText(
            self, "Name this recent case", "Operator-selected case name"
        )
        if not accepted:
            return
        try:
            row = RecentCase(
                name=name.strip(),
                path=str(case.path.absolute()),
                case_id=case.analysis.run_id,
                kind="analysis",
            )
            self.manager.update(self.manager.value.remembering(row))
        except ValueError:
            self.save_status.setText(
                "Use a short plain case name and a safe local path; no entry was stored."
            )

    def reopen(self) -> None:
        index = self.recent.currentRow()
        if not 0 <= index < len(self.manager.value.recent):
            return
        row = self.manager.value.recent[index]
        if row.kind == "analysis":
            self.host_window.controller.open_analysis(Path(row.path))
        else:
            self.host_window.controller.analyze_bundle(Path(row.path))

    def remove_entry(self) -> None:
        index = self.recent.currentRow()
        if 0 <= index < len(self.manager.value.recent):
            self.change(
                recent=[
                    row.model_dump(mode="json")
                    for position, row in enumerate(self.manager.value.recent)
                    if position != index
                ]
            )

    def choose_work_root(self) -> None:
        controller = self.host_window.controller
        if controller.busy:
            self.save_status.setText(
                "Wait for the current diagnostic operation before changing work location."
            )
            return
        selected = QFileDialog.getExistingDirectory(
            self,
            "Choose a local parent; a new private work folder will be created",
            controller.dialog_directory(),
        )
        if not selected:
            return
        root = Path(selected).absolute() / ("WFDiag-Work-" + uuid4().hex[:12])

        def prepare() -> object:
            from wfdiag.gui.controller import prepare_work_root

            return prepare_work_root(root)

        def changed(value: object) -> None:
            if not isinstance(value, Path):
                return
            if controller.lock is not None:
                controller.lock.unlock()
                controller.lock = None
            if controller.jobs is not None:
                controller.jobs.deleteLater()
                controller.jobs = None
            controller.root = value
            self.host_window.work_location_label.setText(str(value))
            self.change(work_root=str(value))
            controller.message("Private work folder ready.")

        controller.run_local(prepare, changed)

    def help(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Local help, notices and signing")
        dialog.resize(820, 650)
        body = QVBoxLayout(dialog)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setAccessibleName("Local operator help and dependency notices")
        notices = (
            "Dependency notices are unavailable in this build; package validation is unfinished."
        )
        try:
            with files("wfdiag").joinpath("resources/notices.txt").open("rb") as source:
                data = source.read(1024 * 1024 + 1)
            if len(data) <= 1024 * 1024:
                notices = data.decode("utf-8")
        except (OSError, UnicodeError):
            pass
        view.setPlainText(HELP + "\n\nThird-party notices\n\n" + notices)
        body.addWidget(view)
        close = QPushButton("Close local help")
        close.clicked.connect(dialog.close)
        body.addWidget(close)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.show()
