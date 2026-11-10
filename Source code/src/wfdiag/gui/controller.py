"""Explicit desktop actions; I/O and result parsing run away from the event loop."""

import json
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from PySide6.QtCore import (
    QElapsedTimer,
    QLockFile,
    QObject,
    QRunnable,
    QStandardPaths,
    Qt,
    QThreadPool,
    QTimer,
    Signal,
)
from PySide6.QtWidgets import QFileDialog, QMessageBox

from wfdiag.contracts.comparison import Comparison
from wfdiag.contracts.desktop_job import DesktopRequest, RequestBase, decode_request
from wfdiag.contracts.doctor import DoctorReport
from wfdiag.contracts.models import Analysis, Intent, Manifest, Proposal
from wfdiag.gui.elevation import PermissionDeclined, PermissionProcess, request_collection
from wfdiag.gui.installation import EngineInstallationUnavailable, verify_frozen_installation
from wfdiag.gui.jobs import DesktopJobs
from wfdiag.storage.analysis_index import AnalysisIndex, read_gui_analysis
from wfdiag.storage.atomic_write import write_new_bytes
from wfdiag.storage.bundle import VerifiedBundle
from wfdiag.storage.private_output import create_private_directory, verify_private_directory
from wfdiag.version import __version__

if TYPE_CHECKING:
    from wfdiag.gui.main_window import MainWindow


GUIDED_INTENT_ERROR = (
    "Check the application details. Use general review if you do not know the destination, "
    "service port or network profile."
)


class InvalidCaseFolder(ValueError):
    """The chosen folder has neither supported case entry file."""


class InvalidAnalysisFile(ValueError):
    """A comparison selection is not a validated saved analysis."""


def default_work_root() -> Path:
    parent = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.GenericDataLocation)
    if not parent:
        raise OSError("Per-user local application data is unavailable")
    return Path(parent) / "WFDiag-FirewallAssistant"


def prepare_work_root(root: Path) -> Path:
    held = verify_private_directory(root) if root.exists() else create_private_directory(root)
    if held is not None:
        held.close()
    return root


class LocalTask(QRunnable):
    def __init__(self, owner: "WindowController", action: Callable[[], object]) -> None:
        super().__init__()
        self.owner, self.action = owner, action

    def run(self) -> None:
        try:
            value = self.action()
        except EngineInstallationUnavailable:
            self.owner.loaded.emit(None, "ENGINE_INSTALLATION_UNAVAILABLE")
        except InvalidCaseFolder:
            self.owner.loaded.emit(None, "CASE_FILES_MISSING")
        except InvalidAnalysisFile:
            self.owner.loaded.emit(None, "ANALYSIS_FILE_REQUIRED")
        except (OSError, ValueError):
            self.owner.loaded.emit(None, "LOCAL_INPUT_OR_PRIVATE_STORAGE_UNAVAILABLE")
        except Exception:  # noqa: BLE001 -- task boundary must report failure, never stay busy.
            self.owner.loaded.emit(None, "LOCAL_OPERATION_FAILED")
        else:
            self.owner.loaded.emit(value, "")


class WindowController(QObject):
    operation_done = Signal(object, object)
    operation_failed = Signal(str, int)
    loaded = Signal(object, str)

    def __init__(self, window: "MainWindow") -> None:
        super().__init__(window)
        self.window = window
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)
        self.jobs: DesktopJobs | None = None
        self.root: Path | None = None
        self.last_bundle: Path | None = None
        self.lock: QLockFile | None = None
        self.busy = False
        self.cancel_requested = False
        self.stage = ""
        self.after_load: Callable[[object], None] | None = None
        self.elapsed = QElapsedTimer()
        self.guided_run = False
        self.permission_attempted = False
        self.permission_process: PermissionProcess | None = None
        self.permission_request: DesktopRequest | None = None
        self.permission_timer = QTimer(self)
        self.permission_timer.setInterval(200)
        self.permission_timer.timeout.connect(self.poll_permission)
        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self.update_elapsed)
        self.loaded.connect(self.local_completed, Qt.ConnectionType.QueuedConnection)

    def set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.window.case_view.busy = busy
        self.window.cancel_button.setEnabled(busy)
        self.window.analyze_collected_button.setEnabled(not busy and self.last_bundle is not None)
        for control in self.window.operation_buttons:
            control.setEnabled(not busy)
        if busy:
            self.cancel_requested = False
            self.elapsed.start()
            self.timer.start()
        else:
            self.timer.stop()
        self.window.case_view.refresh_status()
        if busy:
            for control in (
                self.window.case_view.share_button,
                self.window.case_view.full_button,
                self.window.case_view.proposal_button,
            ):
                control.setEnabled(False)
        elif self.window.case_view.analysis is not None:
            available = self.window.case_view.path is not None or self.window.case_view.synthetic
            self.window.case_view.share_button.setEnabled(available)
            self.window.case_view.full_button.setEnabled(available)

    def message(self, text: str) -> None:
        self.window.job_status.setText(text)
        self.window.investigation_status.setText(text)
        self.window.statusBar().showMessage(text)

    def dialog_directory(self) -> str:
        if self.root is not None and self.root.is_dir():
            return str(self.root)
        default = default_work_root()
        for directory in (default, default.parent):
            if directory.is_dir():
                return str(directory)
        return str(Path.home())

    def start_guided(self) -> None:
        if self.busy:
            return
        try:
            self.window.intent_form.value()
        except ValueError:
            self.message(GUIDED_INTENT_ERROR)
            return
        self.guided_run = True
        self.permission_attempted = False
        self.submit("doctor", {})

    def collect_with_permission(self) -> None:
        """Only a deliberate GUI click/consent calls this; never an AI action."""
        if self.busy:
            return
        self.guided_run = True
        root = self.root or default_work_root()
        minutes = self.window.collection_minutes.value()
        out = root / ("permission-case-" + str(uuid4()))

        def prepare() -> Path:
            verify_frozen_installation()
            prepare_work_root(root)
            held = create_private_directory(out)
            if held is not None:
                held.close()
            return out

        def launch(value: object) -> None:
            if not isinstance(value, Path):
                return
            try:
                if self.lock is None:
                    self.lock = QLockFile(str(root / ".desktop-session.lock"))
                    self.lock.setStaleLockTime(0)
                    if not self.lock.tryLock(0):
                        self.lock = None
                        raise OSError("Work location already in use")
                self.root = root
                self.permission_request = decode_request(
                    json.dumps(
                        {
                            "protocol_version": 1,
                            "job_id": str(uuid4()),
                            "operation": "collect",
                            "expected_engine_version": __version__,
                            "parameters": {"out": str(value), "minutes": minutes},
                        }
                    ).encode()
                )
                self.stage = "Waiting for Windows permission"
                self.set_busy(True)
                self.update_elapsed()
                self.permission_process = request_collection(
                    value, minutes, int(self.window.winId())
                )
                self.permission_attempted = True
                self.stage = "Reading evidence with Windows permission; no settings are changed"
                self.permission_timer.start()
            except PermissionDeclined:
                self.set_busy(False)
                self.guided_run = False
                self.message(
                    "Windows permission was cancelled. No administrator collection started. You can retry or collect the available evidence without administrator access."
                )
            except (OSError, ValueError):
                self.set_busy(False)
                self.guided_run = False
                self.message(
                    "Windows could not start the permission collector. Use the complete extracted application folder; existing evidence is retained. Administrator access may be restricted by your organization."
                )

        self.run_local(prepare, launch)

    def poll_permission(self) -> None:
        process = self.permission_process
        if process is None:
            return
        try:
            code = process.poll()
            status_known = True
        except OSError:
            self.cancel()
            code = 6
            status_known = False
        if code is None:
            return
        self.permission_timer.stop()
        process.close()
        self.permission_process = None
        request, self.permission_request = self.permission_request, None
        cancelled = self.cancel_requested
        self.set_busy(False)
        if cancelled:
            self.guided_run = False
            self.cancelled(status_known)
            return
        if request is None or code not in (0, 5):
            self.guided_run = False
            self.message(
                "Administrator collection did not complete. Windows may still restrict the log, or the private destination may belong to a different Windows account. Existing evidence is retained."
            )
            self.operation_failed.emit("PERMISSION_COLLECTION_FAILED", code)
            return
        out = Path(request.parameters.out)

        def validate() -> Manifest:
            with VerifiedBundle(out) as bundle:
                for _ in bundle.iter_events():
                    pass
                if bundle.manifest.collector_version != __version__:
                    raise ValueError("Collector version differs")
                return bundle.manifest

        def accepted(value: object) -> None:
            if isinstance(value, Manifest):
                self.completed(request, value)

        self.run_local(validate, accepted)

    def update_elapsed(self) -> None:
        self.message(
            f"{'Cancel requested; waiting for bounded cleanup' if self.cancel_requested else self.stage} · {self.elapsed.elapsed() // 1000}s"
        )

    def run_local(self, action: Callable[[], object], done: Callable[[object], None]) -> None:
        if self.busy:
            return
        self.after_load = done
        self.stage = "Validating selected input"
        self.set_busy(True)
        self.update_elapsed()
        self.pool.start(LocalTask(self, action))

    def local_completed(self, value: object, error: str) -> None:
        done, self.after_load = self.after_load, None
        cancelled = self.cancel_requested
        self.set_busy(False)
        if cancelled:
            if isinstance(value, AnalysisIndex):
                value.close()
            self.message("Cancelled · Local preparation stopped; no worker started")
            self.operation_failed.emit("CANCELLED", 5)
        elif error:
            if error == "ENGINE_INSTALLATION_UNAVAILABLE":
                self.message(
                    "Engine unavailable · Restore the complete matching application folder from the trusted reviewed ZIP and verify its checksum. Keep both executables and _internal together. No worker started; do not search PATH or bypass security controls."
                )
            elif error == "CASE_FILES_MISSING":
                self.message(
                    "No case found in this folder. Choose the collected case folder containing manifest.json, or an analysis folder containing analysis.json. Keep all of its original files together."
                )
            elif error == "ANALYSIS_FILE_REQUIRED":
                for label in self.window.comparison_paths.values():
                    if label.text().startswith("Checking"):
                        label.setText(
                            "Not a saved analysis. Choose analysis.json from a completed investigation."
                        )
                self.message(
                    "Compare needs a saved analysis result (analysis.json or the bundled expected-analysis.json). network.json, rules.json and manifest.json are raw case files, not analysis results. Choose the analysis produced after Analyze."
                )
            else:
                self.message(
                    f"Failed · {error}. Select a valid local input or a verified private work location."
                )
            self.operation_failed.emit(error, 2)
        elif done is not None:
            done(value)

    def open_analysis(self, path: Path) -> None:
        def bound(value: object) -> None:
            if isinstance(value, (Analysis, AnalysisIndex)):
                self.bind(value, path)

        self.run_local(lambda: read_gui_analysis(path), bound)

    def load_page(self, page: int) -> None:
        view = self.window.case_view
        index = view.result_index
        if index is None:
            return

        def bound(value: object) -> None:
            if isinstance(value, Analysis) and view.result_index is index:
                view.display_page(value, page)
                self.window.ai_destination.invalidate()
                self.message("Findings page loaded · Search covers this page only")

        self.run_local(lambda: index.read_page(page), bound)

    def example(self) -> None:
        def read() -> Analysis:
            data = files("wfdiag").joinpath("gui/resources/synthetic-analysis.json").read_bytes()
            if len(data) > 128 * 1024:
                raise ValueError("Invalid bundled example")
            result = Analysis.model_validate_json(data)
            if result.engine_version != __version__:
                raise ValueError("Bundled example version differs")
            return result

        def bound(value: object) -> None:
            if isinstance(value, Analysis):
                self.bind(value, None, synthetic=True)

        self.run_local(read, bound)

    def bind(
        self, result: Analysis | AnalysisIndex, path: Path | None, *, synthetic: bool = False
    ) -> None:
        analysis = result.metadata if isinstance(result, AnalysisIndex) else result
        if analysis.engine_version != __version__:
            if isinstance(result, AnalysisIndex):
                result.close()
            self.message(
                "Unsupported · Analysis engine version differs from this application; no active case was replaced"
            )
            self.operation_failed.emit("UNSUPPORTED_ENGINE_VERSION", 3)
            return
        self.window.case_view.bind(result, path, synthetic=synthetic)
        events = next((s for s in analysis.sources if s.source == "events"), None)
        self.window.case_view.permission_button.setVisible(
            not synthetic
            and not self.permission_attempted
            and events is not None
            and events.state.value == "access_denied"
        )
        self.window.ai_destination.invalidate()
        self.window.example_open = synthetic
        self.window.case_tabs.setCurrentIndex(0)
        self.window.navigate(2)
        self.intent_changed()
        self.message(
            f"{'Synthetic example' if synthetic else 'Analysis loaded'} · Evidence {analysis.completeness.value}; this is not a security verdict"
        )

    def intent_changed(self) -> None:
        if not self.busy and self.window.job_status.text() == GUIDED_INTENT_ERROR:
            self.message(
                "Application details changed. Choose Start investigation to check them."
                if self.window.intent_form.enabled.isChecked()
                else "General review selected. Choose Start investigation."
            )
        view = self.window.case_view
        if view.analysis is None or view.synthetic:
            return
        try:
            current = self.window.intent_form.value()
        except ValueError:
            view.stale = True
        else:
            # Imported analysis is usable with its captured intent until this session's
            # operator deliberately enables/edits intent. Clearing edited intent is stale.
            view.stale = current != view.analysis.intent if self.window.intent_touched else False
        view.refresh_status()
        if self.busy:
            view.proposal_button.setEnabled(False)

    def submit(
        self, operation: str, parameters: dict[str, object], *, intent: Intent | None = None
    ) -> None:
        if self.busy:
            return
        job_id = str(uuid4())
        root = self.root or default_work_root()

        def prepare() -> DesktopRequest:
            verify_frozen_installation()
            prepare_work_root(root)
            values = dict(parameters)
            if "out" not in values:
                values["out"] = str(
                    root
                    / (
                        f"{operation}-{job_id}"
                        if operation in ("analyze", "collect")
                        else f"{operation}-{job_id}.json"
                    )
                )
            if intent is not None:
                path = root / f"intent-{job_id}.json"
                write_new_bytes(path, intent.model_dump_json().encode(), byte_limit=64 * 1024)
                values["intent"] = str(path)
            return decode_request(
                json.dumps(
                    {
                        "protocol_version": 1,
                        "job_id": job_id,
                        "operation": operation,
                        "expected_engine_version": __version__,
                        "parameters": values,
                    }
                ).encode()
            )

        def launch(value: object) -> None:
            # The protocol union is validated by decode_request before reaching here.
            request = (
                decode_request(value.model_dump_json().encode())
                if isinstance(value, RequestBase)
                else None
            )
            if request is None:
                self.message("Failed · Invalid prepared request")
                self.operation_failed.emit("INVALID_PREPARED_REQUEST", 2)
                return
            try:
                if self.jobs is None:
                    if self.lock is None:
                        self.lock = QLockFile(str(root / ".desktop-session.lock"))
                        self.lock.setStaleLockTime(0)
                        locked = self.lock.tryLock(0)
                    else:
                        locked = True
                    if not locked:
                        self.message(
                            "Unavailable · Another desktop instance owns this private work location. Close it before starting a job."
                        )
                        self.lock = None
                        self.operation_failed.emit("WORK_LOCATION_IN_USE", 4)
                        return
                    self.root = root
                    self.window.work_location_label.setText(f"Private work location: {root}")
                    self.jobs = DesktopJobs(root, self)
                    self.jobs.progress.connect(self.progress)
                    self.jobs.completed.connect(self.completed)
                    self.jobs.failed.connect(self.failed)
                    self.jobs.cancelled.connect(self.cancelled)
                self.stage = f"Running {request.operation}"
                self.set_busy(True)
                self.update_elapsed()
                self.jobs.start(request)
            except (OSError, ValueError):
                self.set_busy(False)
                self.message(
                    "Failed · Private job storage or the installed engine is unavailable. Restore the complete matching application folder and verify its checksum; do not substitute an engine from PATH."
                )
                self.operation_failed.emit("ENGINE_OR_PRIVATE_STORAGE_UNAVAILABLE", 4)

        self.run_local(prepare, launch)

    def progress(self, stage: str) -> None:
        self.stage = "Running " + stage.replace("-", " ")[:100]
        # Coalesce progress onto the existing 500ms timer rather than per-frame refresh.

    def completed(self, request: DesktopRequest, result: object) -> None:
        self.set_busy(False)
        if request.operation == "analyze" and isinstance(result, (Analysis, AnalysisIndex)):
            self.bind(result, Path(request.parameters.out))
        elif request.operation == "collect" and isinstance(result, Manifest):
            self.last_bundle = Path(request.parameters.out)
            self.window.analyze_collected_button.setEnabled(True)
            self.message(
                f"Case collected · Evidence {result.completeness.value}. Review source gaps, then choose Analyze collected case. The firewall was not changed."
            )
            self.window.explain_collection(result, self.permission_attempted)
        elif isinstance(result, DoctorReport):
            states = " · ".join(f"{c.name}: {c.state}" for c in result.capabilities)
            self.window.preflight_result.setPlainText(
                f"Windows build {result.host.build} · {result.host.architecture}\nTarget eligible: {result.eligible_target}\n{result.support_note}\n{states}"
            )
            self.message("Preflight completed · No security events or firewall policy collected")
            self.window.explain_access(result)
        elif isinstance(result, Comparison):
            self.window.comparison_result.setPlainText(
                f"Before: {result.before_analyzed_at_utc.isoformat()} ({result.before_completeness.value})\nAfter: {result.after_analyzed_at_utc.isoformat()} ({result.after_completeness.value})\nObservations: {result.observation_change}\nPolicy comparison: {result.policy_comparison}\nRule changes: {len(result.rule_changes)}; profile changes: {len(result.profile_changes)}\nWarnings: {', '.join(result.warnings)}\n\n{result.conclusion}"
            )
            self.message("Comparison completed · Repair is not established")
        elif isinstance(result, Proposal):
            self.window.case_view.proposal.setPlainText(result.model_dump_json(indent=2))
            self.message("Proposal exported · Nonexecuting JSON; independent review required")
        else:
            self.message("Report exported · Review the new local file before sharing")
        self.operation_done.emit(request, result)
        if self.guided_run and isinstance(result, DoctorReport):
            self.window.continue_guided(result)
        elif self.guided_run and request.operation == "collect":
            self.guided_run = False
            self.analyze_collected()

    def failed(self, reason: str, code: int) -> None:
        self.guided_run = False
        self.set_busy(False)
        explanations = {
            2: "Input or output was refused",
            3: "Capability unsupported or unavailable",
            4: "Access denied",
            5: "Incomplete or cancelled",
            6: "Worker or output validation failed",
        }
        repair = (
            " Restore the complete matching application folder from the trusted reviewed ZIP and verify its checksum; do not bypass security controls."
            if reason
            in (
                "ENGINE_START_FAILED",
                "ENGINE_VERSION_MISMATCH",
                "UNSUPPORTED_ENGINE_VERSION",
                "WORKER_PROTOCOL_OR_PROCESS_FAILED",
            )
            else ""
        )
        self.message(
            f"{explanations.get(code, 'Operation failed')} · {reason[:100]}. No completion was reported. Inputs and intended flow are retained.{repair}"
        )
        self.operation_failed.emit(reason, code)

    def cancel(self) -> None:
        if self.busy:
            self.cancel_requested = True
            self.update_elapsed()
            if self.permission_process is not None and self.permission_request is not None:
                path = Path(self.permission_request.parameters.out)
                try:
                    write_new_bytes(
                        path.parent / (path.name + ".cancel"), b"cancel\n", byte_limit=32
                    )
                except FileExistsError:
                    pass
                except (OSError, ValueError):
                    self.message(
                        "Cancellation could not be recorded. Waiting for the bounded administrator collector; interrupted output will not be treated as complete."
                    )
            if self.jobs is not None and self.jobs.busy:
                self.jobs.cancel()

    def cancelled(self, confirmed: bool) -> None:
        self.guided_run = False
        self.set_busy(False)
        self.message(
            "Cancelled · "
            + (
                "Worker cleanup confirmed; start a fresh job"
                if confirmed
                else "Cleanup unconfirmed; interrupted outputs must not be treated as complete"
            )
        )
        self.operation_failed.emit("CANCELLED", 5)

    def analyze_bundle(self, path: Path) -> None:
        try:
            intent = self.window.intent_form.value()
        except ValueError:
            self.message(
                "Invalid intended flow · Choose one profile, a verified local program path, approved peer scope, service port and purpose"
            )
            self.operation_failed.emit("INTENDED_FLOW_INVALID", 2)
            return
        self.submit("analyze", {"bundle": str(path.absolute())}, intent=intent)

    def analyze_collected(self) -> None:
        if self.last_bundle is not None:
            self.analyze_bundle(self.last_bundle)

    def report_source(self, ready: Callable[[Path], None]) -> None:
        """Persist only the validated training example when an export needs a file."""
        view = self.window.case_view
        if view.path is not None:
            ready(view.path)
            return
        analysis = view.analysis
        if analysis is None or not view.synthetic:
            return
        root = self.root or default_work_root()

        def prepare() -> Path:
            prepare_work_root(root)
            output = root / f"training-example-{uuid4()}"
            held = create_private_directory(output)
            try:
                path = output / "analysis.json"
                write_new_bytes(path, analysis.model_dump_json().encode(), byte_limit=128 * 1024)
                return path
            finally:
                if held is not None:
                    held.close()

        def prepared(value: object) -> None:
            if isinstance(value, Path) and view.analysis is analysis and view.synthetic:
                view.path = value
                ready(value)
            else:
                self.operation_failed.emit("EXAMPLE_CONTEXT_CHANGED", 2)

        self.run_local(prepare, prepared)

    def choose_output(
        self, title: str, filename: str, file_filter: str, selected: Callable[[Path], None]
    ) -> None:
        root = self.root or default_work_root()
        previous_status = self.window.job_status.text()

        def choose(value: object) -> None:
            if not isinstance(value, Path):
                return
            self.message(previous_status)
            name = Path(filename)
            suggestion = value / f"{name.stem}-{uuid4().hex[:12]}{name.suffix}"
            target, _ = QFileDialog.getSaveFileName(
                self.window, title, str(suggestion), file_filter
            )
            if target:
                selected(Path(target).absolute())

        self.run_local(lambda: prepare_work_root(root), choose)

    def export_report(self, full: bool = False) -> None:
        view = self.window.case_view
        if view.analysis is None:
            return
        if (
            full
            and QMessageBox.warning(
                self.window,
                "Sensitive local full report",
                "Full reports contain application paths, addresses, rule details and local evidence. Export only to a verified private folder. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return

        def selected(target: Path) -> None:
            self.report_source(
                lambda source: self.submit(
                    "report",
                    {
                        "analysis": str(source),
                        "mode": "full" if full else "share",
                        "out": str(target),
                    },
                )
            )

        self.choose_output(
            "Export local full report" if full else "Export redacted share report",
            "full.html" if full else "share.html",
            "Reports (*.html *.json)",
            selected,
        )

    def export_proposal(self) -> None:
        view = self.window.case_view
        source, analysis = view.path, view.analysis
        finding = view.selected()
        if (
            source is None
            or analysis is None
            or view.stale
            or view.synthetic
            or finding is None
            or not finding.proposal_eligible
            or analysis.intent is None
        ):
            return

        def selected(target: Path) -> None:
            if view.analysis is not analysis or view.path != source or view.stale:
                self.message("The analysis changed. Recheck the current finding before exporting.")
                return
            self.submit(
                "propose",
                {
                    "analysis": str(source),
                    "finding_id": finding.finding_id,
                    "out": str(target),
                },
                intent=analysis.intent,
            )

        self.choose_output(
            "Export nonexecuting proposal to a private folder",
            "proposal.json",
            "Proposal JSON (*.json)",
            selected,
        )
