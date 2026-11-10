"""Desktop workspace backed by the shared local engine. Optional AI stays separate."""

from importlib.resources import files
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices, QIcon, QPalette, QResizeEvent
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from wfdiag.contracts.doctor import DoctorReport
from wfdiag.contracts.models import Manifest
from wfdiag.gui.ai_destination import AiDestination
from wfdiag.gui.controller import InvalidAnalysisFile, InvalidCaseFolder, WindowController
from wfdiag.gui.forms import CaseView, IntentForm
from wfdiag.gui.icons import line_icon
from wfdiag.gui.preferences import Preferences, PreferenceStore
from wfdiag.gui.settings import PreferenceManager, SettingsView
from wfdiag.gui.theme import DARK, LIGHT, apply_theme
from wfdiag.storage.analysis_index import AnalysisIndex, read_gui_analysis
from wfdiag.version import DISPLAY_VERSION

AUTHOR_LINKS = {
    "GitHub": "https://github.com/The-Real-Virus",
    "LinkedIn": "https://www.linkedin.com/in/syed-muhammad-shah",
}


def label(text: str, kind: str = "", wrap: bool = True) -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(wrap)
    widget.setTextInteractionFlags(
        Qt.TextInteractionFlag.TextSelectableByMouse
        | Qt.TextInteractionFlag.TextSelectableByKeyboard
    )
    if kind:
        widget.setObjectName(kind)
    return widget


def button(text: str, primary: bool = False) -> QPushButton:
    widget = QPushButton(text)
    widget.setAccessibleName(text.replace("&", ""))
    if primary:
        widget.setObjectName("primary")
    return widget


def panel() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(24, 24, 24, 24)
    layout.setSpacing(16)
    return frame, layout


def plain_text(text: str) -> QPlainTextEdit:
    edit = QPlainTextEdit(text)
    edit.setReadOnly(True)
    edit.setAccessibleName("Local example details")
    return edit


class MainWindow(QMainWindow):
    controller: WindowController
    collection_minutes: QSpinBox
    work_location_label: QLabel
    theme_selection: str
    destinations = ("Overview", "Diagnose", "Cases", "Compare", "Settings", "AI Assistant")

    def __init__(
        self,
        preferences: Preferences | None = None,
        preference_store: PreferenceStore | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle(f"Firewall Assistant — {DISPLAY_VERSION}")
        self.setWindowIcon(QIcon(str(files("wfdiag").joinpath("gui/resources/app.ico"))))
        self.resize(1280, 840)
        self.setMinimumSize(1000, 700)
        self.preferences = PreferenceManager(self, preferences or Preferences(), preference_store)
        self.theme_selection = self.preferences.value.theme
        self.example_open = False
        self.intent_touched = False
        self.operation_buttons: list[QPushButton] = []
        self.close_pending = False
        outer = QWidget()
        self.setCentralWidget(outer)
        layout = QHBoxLayout(outer)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.rail = QFrame()
        self.rail.setObjectName("rail")
        self.rail.setFixedWidth(216)
        nav = QVBoxLayout(self.rail)
        nav.setContentsMargins(16, 28, 16, 20)
        nav.setSpacing(8)
        nav.addWidget(label("Firewall\nAssistant", "brand"))
        nav.addSpacing(24)
        self.nav_buttons: dict[str, QPushButton] = {}
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for index, name in enumerate(self.destinations):
            if name == "Settings":
                nav.addStretch()
            if name == "AI Assistant":
                nav.addSpacing(12)
            item = button(name)
            item.setObjectName("nav")
            item.setCheckable(True)
            item.clicked.connect(
                lambda checked=False, destination=index: self.navigate(destination)
            )
            self.nav_group.addButton(item, index)
            self.nav_buttons[name] = item
            nav.addWidget(item)
        nav.addSpacing(12)
        self.rail_footer = QWidget()
        footer = QVBoxLayout(self.rail_footer)
        footer.setContentsMargins(10, 0, 0, 0)
        footer.setSpacing(6)
        self.version_label = label(DISPLAY_VERSION, "footerMeta")
        self.ai_status_label = label("AI is off", "footerMeta")
        self.maker_label = label("Made By ViRuS", "watermark")
        footer.addWidget(self.version_label)
        footer.addWidget(self.ai_status_label)
        footer.addWidget(self.maker_label)
        social = QHBoxLayout()
        social.setSpacing(8)
        self.profile_buttons: dict[str, QToolButton] = {}
        for name, url in AUTHOR_LINKS.items():
            profile = QToolButton()
            profile.setObjectName("profileLink")
            profile.setFixedSize(36, 36)
            profile.setIconSize(QSize(22, 22))
            profile.setAccessibleName(f"Open ViRuS on {name} in your browser")
            profile.setToolTip(f"{name} · {url}\nOpens your default browser")
            profile.setCursor(Qt.CursorShape.PointingHandCursor)
            profile.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            profile.clicked.connect(lambda checked=False, site=name: self.open_author_profile(site))
            self.profile_buttons[name] = profile
            social.addWidget(profile)
        social.addStretch()
        footer.addLayout(social)
        self.copyright_label = label("© 2026 ViRuS.\nAll rights reserved.", "copyright")
        footer.addWidget(self.copyright_label)
        nav.addWidget(self.rail_footer)
        layout.addWidget(self.rail)
        self.pages = QStackedWidget()
        layout.addWidget(self.pages, 1)
        self.pages.addWidget(self.overview())
        self.pages.addWidget(self.diagnose())
        self.pages.addWidget(self.cases())
        self.pages.addWidget(self.compare())
        self.pages.addWidget(self.settings())
        self.pages.addWidget(self.ai_assistant())
        self.cancel_button = button("Request cancellation")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(lambda: self.controller.cancel())
        self.statusBar().addPermanentWidget(self.cancel_button)
        self.controller = WindowController(self)
        if self.preferences.value.work_root is not None:
            self.controller.root = Path(self.preferences.value.work_root)
        self.table.selectionModel().currentChanged.connect(self.ai_destination.invalidate)
        self.statusBar().showMessage("Ready · Local diagnostics available")
        self.navigate(0)
        self.update_icons()

    def page(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        content = QWidget()
        content.setObjectName("page")
        content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 28, 32, 24)
        layout.setSpacing(20)
        layout.addWidget(label(title, "title"))
        layout.addWidget(label(subtitle, "muted"))
        return content, layout

    def scroll_page(self, content: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        return scroll

    def overview(self) -> QWidget:
        content, layout = self.page(
            "Why can't this application connect?",
            "Investigate a failed connection using Windows firewall evidence.",
        )
        layout.addWidget(
            label("Local diagnostics · Optional AI · No automatic policy changes", "badge")
        )
        frame, body = panel()
        body.addWidget(label("Investigate a real connection problem", "section"))
        body.addWidget(
            label(
                "First try the application that cannot connect. Then collect recent firewall settings and blocking-event logs. We will explain what the evidence supports, or exactly what is missing.",
                "muted",
            )
        )
        actions = QHBoxLayout()
        start = button("Investigate a &connection", True)
        start.clicked.connect(lambda: self.navigate(1))
        actions.addWidget(start)
        opened = button("Open case folder")
        opened.clicked.connect(self.choose_case)
        self.operation_buttons.append(opened)
        actions.addWidget(opened)
        actions.addStretch()
        body.addLayout(actions)
        body.addWidget(
            label(
                "Your firewall stays enabled. Collection and analysis work without AI or internet. Nothing is repaired or changed automatically.",
                "warning",
            )
        )
        layout.addWidget(frame)
        example, example_body = panel()
        example_body.addWidget(label("Explore an example", "section"))
        example_body.addWidget(
            label(
                "See a made-up connection problem and its explanation. This training example does not inspect your computer and its findings are not about you.",
                "muted",
            )
        )
        open_example = button("Open &example")
        open_example.clicked.connect(self.open_example)
        self.operation_buttons.append(open_example)
        example_body.addWidget(open_example, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(example)
        layout.addStretch()
        return self.scroll_page(content)

    def diagnose(self) -> QWidget:
        content, layout = self.page(
            "Investigate a connection",
            "Try the failing connection first, then follow the steps below.",
        )
        frame, body = panel()
        body.addWidget(label("1 · Choose the investigation", "section"))
        body.addWidget(
            label(
                "General review needs no technical connection details. To focus on one application, enable the optional questions below. Do not invent addresses or ports just to fill the form.",
                "muted",
            )
        )
        self.intent_form = IntentForm()
        self.intent_form.changed.connect(self.intent_edited)
        body.addWidget(self.intent_form)
        body.addWidget(label("2 · Gather evidence and get an explanation", "section"))
        self.start_guided_button = button("Start investigation", True)
        self.start_guided_button.clicked.connect(lambda: self.controller.start_guided())
        self.operation_buttons.append(self.start_guided_button)
        body.addWidget(self.start_guided_button)
        self.access_summary = label(
            "Windows access is checked first. If blocking logs need administrator permission, you will be asked before a separate read-only collector starts."
        )
        body.addWidget(self.access_summary)
        self.permission_button = button("Ask Windows for permission to collect", True)
        self.permission_button.clicked.connect(lambda: self.controller.collect_with_permission())
        self.permission_button.hide()
        self.operation_buttons.append(self.permission_button)
        body.addWidget(self.permission_button)
        body.addWidget(
            label(
                "The firewall stays enabled. Only existing settings and logs are read. Reproduce a real failure before starting; the default lookback is10 minutes.",
                "muted",
            )
        )
        self.investigation_status = label(
            "Ready · Start investigation checks access, collects evidence and explains the result."
        )
        body.addWidget(self.investigation_status)
        manual_toggle = QToolButton()
        manual_toggle.setText("Manual steps, time window and access details")
        manual_toggle.setCheckable(True)
        body.addWidget(manual_toggle, 0, Qt.AlignmentFlag.AlignLeft)
        manual_steps = QWidget()
        body.addWidget(manual_steps)
        body = QVBoxLayout(manual_steps)
        body.setContentsMargins(0, 8, 0, 0)
        body.setSpacing(12)
        manual_steps.hide()
        manual_toggle.toggled.connect(manual_steps.setVisible)
        run = button("Run preflight", True)
        run.clicked.connect(lambda: self.controller.submit("doctor", {}))
        self.operation_buttons.append(run)
        run.setText("Check access only")
        body.addWidget(run, 0, Qt.AlignmentFlag.AlignLeft)
        self.preflight_result = plain_text(
            "Preflight has not run. No evidence is collected on startup."
        )
        self.preflight_result.setMaximumHeight(140)
        self.preflight_result.setAccessibleName("Actual preflight capabilities")
        access_details = QToolButton()
        access_details.setText("Show technical access details")
        access_details.setCheckable(True)
        access_details.toggled.connect(self.preflight_result.setVisible)
        body.addWidget(access_details, 0, Qt.AlignmentFlag.AlignLeft)
        body.addWidget(self.preflight_result)
        self.preflight_result.hide()
        actions = QHBoxLayout()
        opened = button("Open case folder", True)
        opened.clicked.connect(self.choose_case)
        self.operation_buttons.append(opened)
        actions.addWidget(opened)
        collect = button("Collect local evidence")
        collect.clicked.connect(
            lambda: self.controller.submit("collect", {"minutes": self.collection_minutes.value()})
        )
        self.operation_buttons.append(collect)
        actions.addWidget(collect)
        body.addLayout(actions)
        window_controls = QHBoxLayout()
        window_label = label("Lookback in minutes")
        self.collection_minutes = QSpinBox()
        self.collection_minutes.setRange(1, 60)
        self.collection_minutes.setValue(10)
        self.collection_minutes.setAccessibleName("Existing event lookback in minutes")
        window_label.setBuddy(self.collection_minutes)
        window_controls.addWidget(window_label)
        window_controls.addWidget(self.collection_minutes)
        window_controls.addStretch()
        body.addLayout(window_controls)
        body.addWidget(
            label(
                "Collection reads existing firewall settings and recent blocking events into a private folder. It does not test the connection for you. Start investigation collects and analyzes in sequence; the separate buttons are available for manual steps. Windows permission is requested only after your choice; AI never requests it.",
                "warning",
            )
        )
        self.analyze_collected_button = button("Analyze collected case", True)
        self.analyze_collected_button.setEnabled(False)
        self.analyze_collected_button.clicked.connect(lambda: self.controller.analyze_collected())
        body.addWidget(self.analyze_collected_button, 0, Qt.AlignmentFlag.AlignLeft)
        self.job_status = label("Idle · Choose a case or run preflight")
        self.job_status.setAccessibleName("Current operation and recovery action")
        body.addWidget(self.job_status)
        layout.addWidget(frame)
        layout.addStretch()
        return self.scroll_page(content)

    def explain_access(self, report: DoctorReport) -> None:
        states = {c.name: c.state for c in report.capabilities}
        denied = states.get("security_events") == "denied"
        self.permission_button.setVisible(denied and report.administrator_token is not True)
        if denied:
            self.access_summary.setText(
                "Windows did not allow this session to read blocking-event logs. Firewall settings can still be reviewed, but we cannot determine which connection was blocked without event evidence. Choose the Windows permission button to run only the read-only collector as administrator."
                if report.administrator_token is not True
                else "Windows still restricts blocking-event logs in this administrator session. Permission is not being requested again. An organization policy or log access problem needs administrator review; limited evidence can still be collected."
            )
        elif states.get("security_events") == "supported":
            self.access_summary.setText(
                "Windows allows this session to read the blocking-event log. Collection will check for recorded events in your selected time window; an accessible log may still contain no relevant event."
            )
        else:
            self.access_summary.setText(
                "Blocking-event log availability could not be established. Review the access details; a limited investigation cannot establish whether a connection was blocked."
            )

    def continue_guided(self, report: DoctorReport) -> None:
        states = {c.name: c.state for c in report.capabilities}
        if (
            not report.eligible_target
            or states.get("powershell_51") != "supported"
            or states.get("netsecurity") != "supported"
        ):
            self.controller.guided_run = False
            self.controller.message(
                "Windows collection is unavailable in this session. Review access details or open an existing collected case for offline analysis."
            )
            return
        if states.get("security_events") == "denied" and report.administrator_token is not True:
            prompt = QMessageBox(self)
            prompt.setWindowTitle("Windows permission needed")
            prompt.setText(
                "Windows denied access to blocking-event logs. May Windows ask for administrator permission for a separate read-only collector? Firewall and audit settings will stay unchanged. The GUI and AI stay at normal permissions."
            )
            grant = prompt.addButton(
                "Request Windows permission", QMessageBox.ButtonRole.AcceptRole
            )
            limited = prompt.addButton(
                "Continue with limited evidence", QMessageBox.ButtonRole.ActionRole
            )
            prompt.addButton(QMessageBox.StandardButton.Cancel)
            prompt.exec()
            if prompt.clickedButton() is grant:
                self.controller.collect_with_permission()
                return
            if prompt.clickedButton() is not limited:
                self.controller.guided_run = False
                return
        self.controller.permission_attempted = False
        self.controller.submit("collect", {"minutes": self.collection_minutes.value()})

    def explain_collection(self, manifest: Manifest, administrator_requested: bool) -> None:
        events = next(s for s in manifest.sources if s.source == "events")
        denied = events.state.value == "access_denied"
        self.permission_button.setVisible(denied and not administrator_requested)
        if denied:
            self.access_summary.setText(
                "Evidence was collected, but Windows still denied the blocking-event log. We cannot identify a blocked application from this case. "
                + (
                    "Administrator permission did not resolve the restriction; ask your Windows administrator to review log access."
                    if administrator_requested
                    else "Use the Windows permission button for a separate read-only administrator collection."
                )
            )
        elif events.state.value in ("complete", "empty"):
            self.access_summary.setText(
                f"Blocking-event log read completed: {events.records} recorded events in the selected window. Analysis will explain relevance and any recording limitations."
            )
        else:
            self.access_summary.setText(
                "Collection has missing or incomplete event evidence. Analysis can explain the gaps; it cannot establish a specific blocked connection from missing data."
            )

    def cases(self) -> QWidget:
        self.case_view = CaseView()
        self.case_tabs = self.case_view.tabs
        self.table = self.case_view.table
        self.finding_splitter = self.case_view.splitter
        self.case_view.exportShare.connect(lambda: self.controller.export_report())
        self.case_view.exportFull.connect(lambda: self.controller.export_report(True))
        self.case_view.exportProposal.connect(lambda: self.controller.export_proposal())
        self.case_view.requestPermission.connect(lambda: self.controller.collect_with_permission())
        self.operation_buttons.append(self.case_view.permission_button)
        self.case_view.requestPage.connect(lambda page: self.controller.load_page(page))
        return self.case_view

    def compare(self) -> QWidget:
        content, layout = self.page(
            "Compare cases",
            "Review captured changes and uncertainty; fewer blocks do not prove repair.",
        )
        self.before_path: Path | None = None
        self.after_path: Path | None = None
        frame, body = panel()
        body.addWidget(label("Choose Before and After analyses", "section"))
        self.comparison_paths: dict[str, QLabel] = {}
        for side in ("Before", "After"):
            choose = button(f"Choose {side} analysis")
            choose.clicked.connect(
                lambda checked=False, selected=side: self.choose_comparison(selected)
            )
            self.operation_buttons.append(choose)
            body.addWidget(choose)
            path = label("No analysis selected")
            path.setAccessibleName(f"Local {side} analysis path")
            self.comparison_paths[side] = path
            body.addWidget(path)
        run = button("Compare selected analyses", True)
        run.clicked.connect(self.run_comparison)
        self.operation_buttons.append(run)
        body.addWidget(run)
        self.comparison_result = plain_text("No comparison has run.")
        self.comparison_result.setAccessibleName("Comparison results and uncertainty")
        body.addWidget(self.comparison_result)
        layout.addWidget(frame)
        return self.scroll_page(content)

    def settings(self) -> QWidget:
        self.settings_view = SettingsView(self)
        return self.settings_view

    def ai_assistant(self) -> QWidget:
        self.ai_destination = AiDestination(self)
        return self.ai_destination

    def navigate(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        self.nav_buttons[self.destinations[index]].setChecked(True)

    def open_example(self) -> None:
        self.controller.example()

    def intent_edited(self) -> None:
        self.intent_touched = True
        self.ai_destination.invalidate()
        self.controller.intent_changed()

    def choose_case(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Choose case folder containing manifest.json or analysis.json",
            self.controller.dialog_directory(),
        )
        if not selected:
            return
        path = Path(selected).absolute()

        def inspect() -> object:
            if (path / "analysis.json").is_file():
                return read_gui_analysis(path)
            if (path / "manifest.json").is_file():
                return path
            raise InvalidCaseFolder()

        def opened(value: object) -> None:
            from wfdiag.contracts.models import Analysis

            if isinstance(value, (Analysis, AnalysisIndex)):
                self.controller.bind(value, path)
            elif isinstance(value, Path):
                self.controller.analyze_bundle(value)

        self.controller.run_local(inspect, opened)

    def choose_comparison(self, side: str) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            f"Choose {side} analysis",
            self.controller.dialog_directory(),
            "Analysis JSON (*.json)",
        )
        if selected:
            path = Path(selected).absolute()
            if side == "Before":
                self.before_path = None
            else:
                self.after_path = None
            self.comparison_paths[side].setText("Checking the selected analysis…")

            def inspect() -> Path:
                try:
                    value = read_gui_analysis(path)
                    if isinstance(value, AnalysisIndex):
                        value.close()
                except (OSError, ValueError) as error:
                    raise InvalidAnalysisFile() from error
                return path

            def accepted(value: object) -> None:
                if isinstance(value, Path):
                    if side == "Before":
                        self.before_path = value
                    else:
                        self.after_path = value
                    self.comparison_paths[side].setText(str(value))
                    self.controller.message(
                        "Both analyses are ready. Choose Compare selected analyses."
                        if self.before_path is not None and self.after_path is not None
                        else "Analysis selected. Choose the other analysis to continue."
                    )

            self.controller.run_local(inspect, accepted)

    def run_comparison(self) -> None:
        if self.before_path is None or self.after_path is None:
            self.controller.message("Choose both Before and After analysis files")
            return
        self.controller.submit(
            "compare", {"before": str(self.before_path), "after": str(self.after_path)}
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.controller.busy:
            event.ignore()
            if not self.close_pending:
                answer = QMessageBox.question(
                    self,
                    "Operation in progress",
                    "Cancel the operation and close after it stops? Choose No to keep running in this window.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer == QMessageBox.StandardButton.Yes:
                    self.close_pending = True
                    self.controller.cancel()
            if self.close_pending:
                QTimer.singleShot(100, self.close)
            return
        if not self.ai_destination.shutdown():
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        if not self.preferences.flush():
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        if self.controller.lock is not None:
            self.controller.lock.unlock()
        if self.case_view.result_index is not None:
            self.case_view.result_index.close()
        super().closeEvent(event)

    def set_theme(self, selection: str) -> None:
        self.theme_selection = selection
        if self.preferences.value.theme != selection:
            self.preferences.update(self.preferences.value.changed(theme=selection))
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, selection)
        self.update_icons()

    def update_icons(self) -> None:
        app = QApplication.instance()
        dark = self.theme_selection == "Dark" or (
            self.theme_selection == "System"
            and isinstance(app, QApplication)
            and app.styleHints().colorScheme() == Qt.ColorScheme.Dark
        )
        color = (DARK if dark else LIGHT).secondary
        if self.theme_selection == "High contrast":
            color = self.palette().color(QPalette.ColorRole.WindowText).name()
        for name, item in self.nav_buttons.items():
            item.setIcon(line_icon(name, color))
        for name, profile_button in self.profile_buttons.items():
            profile_button.setIcon(line_icon(name, color))
        self.setWindowIcon(line_icon("Diagnose", color))

    def open_author_profile(self, name: str) -> None:
        target = AUTHOR_LINKS.get(name)
        if target is not None and not QDesktopServices.openUrl(QUrl(target)):
            self.statusBar().showMessage(
                f"Could not open the {name} profile in your browser.", 8000
            )

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        compact = self.width() < 1120
        self.rail.setFixedWidth(168 if compact else 216)
        self.finding_splitter.setOrientation(
            Qt.Orientation.Vertical if compact else Qt.Orientation.Horizontal
        )
