"""Main-thread gateway for the assistant's typed application actions, never OS commands."""

import asyncio
import hashlib
import re
import time
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from wfdiag.ai.assistant import AppAction
from wfdiag.ai.context import SessionAliases
from wfdiag.contracts.comparison import Comparison
from wfdiag.contracts.doctor import DoctorReport
from wfdiag.contracts.models import Manifest, Proposal

if TYPE_CHECKING:
    from wfdiag.gui.main_window import MainWindow


@dataclass
class Pending:
    action: AppAction
    future: Future[dict[str, object]]
    started: float
    operation: str = ""
    result: object = None
    error: str = ""
    return_code: int = 0


class ApplicationTools(QObject):
    requested = Signal(object, object)
    activity = Signal(str, object)
    abort_requested = Signal()

    def __init__(self, window: "MainWindow", parent: QObject) -> None:
        super().__init__(parent)
        self.window = window
        self.aliases = SessionAliases()
        self.references: dict[str, tuple[str, int, str]] = {}
        self.pending: Pending | None = None
        self.artifacts: list[Path] = []
        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.poll)
        self.requested.connect(self.dispatch)
        self.abort_requested.connect(self.cancel)
        window.controller.operation_done.connect(self.completed)
        window.controller.operation_failed.connect(self.failed)

    @property
    def busy(self) -> bool:
        return self.pending is not None

    def revision(self) -> str:
        analysis = self.window.case_view.analysis
        return (
            hashlib.sha256(
                (analysis.run_id + analysis.analyzed_at_utc.isoformat()).encode()
            ).hexdigest()
            if analysis is not None
            else "none"
        )

    def snapshot(self, assistant_page: int | None = None) -> dict[str, object]:
        view = self.window.case_view
        analysis = view.analysis
        state: dict[str, object] = {
            "windows_permission_requires_user_click": True,
            "windows_permission_button_available": not self.window.permission_button.isHidden()
            or not self.window.case_view.permission_button.isHidden(),
            "case_loaded": analysis is not None,
            "engine_busy": self.window.controller.busy,
            "collected_case_available": self.window.controller.last_bundle is not None,
            "comparison_inputs_selected": self.window.before_path is not None
            and self.window.after_path is not None,
        }
        if analysis is None:
            return state
        assistant_page = assistant_page or (view.page_index * 25 + 1)
        total = view.total_findings
        start = (assistant_page - 1) * 20
        offset = start % 500
        page_findings = (
            analysis.findings
            if view.result_index is not None
            else analysis.findings[view.page_index * 500 : (view.page_index + 1) * 500]
        )
        revision = self.revision()
        shown = []
        if len(self.references) > 1024:
            self.references.clear()
        for finding in page_findings[offset : offset + 20]:
            reference = self.aliases.reference(revision, finding.finding_id, "F")
            self.references[reference] = (revision, view.page_index, finding.finding_id)
            shown.append(
                {
                    "reference": reference,
                    "category": finding.category.value,
                    "evidence_grade": finding.evidence_grade.value,
                    "relevance": finding.relevance.value,
                    "proposal_eligible": finding.proposal_eligible,
                    "limitations_count": len(finding.limitations),
                    "alternative_explanations_count": len(finding.alternative_explanations),
                    "next_steps": [step.value for step in finding.next_steps],
                    "refusal_codes": [
                        code
                        for code in finding.refusal_codes
                        if re.fullmatch(r"[A-Z0-9_]{1,64}", code)
                    ],
                }
            )
        state.update(
            {
                "completeness": analysis.completeness.value,
                "total_findings": total,
                "assistant_page": assistant_page,
                "findings": shown,
                "next_page": assistant_page + 1 if start + 20 < total else None,
                "intent_stale": view.stale,
                "synthetic_example": view.synthetic,
                "interpretation": {
                    "supported_does_not_mean_certain": True,
                    "current_policy_is_not_event_time_proof": True,
                    "candidate_rules_are_not_confirmed_causes": True,
                    "private_limitations_available_in_app": True,
                    "repair_established": False,
                },
                "sources": [
                    {
                        "source": s.source,
                        "state": s.state.value,
                        "codes": [
                            c for c in s.warnings[:10] if re.fullmatch(r"[A-Z0-9_]{1,64}", c)
                        ],
                    }
                    for s in analysis.sources
                ],
            }
        )
        return state

    async def execute(self, action: AppAction) -> dict[str, object]:
        future: Future[dict[str, object]] = Future()
        self.requested.emit(action, future)
        try:
            return await asyncio.wrap_future(future)
        except asyncio.CancelledError:
            future.cancel()
            self.abort_requested.emit()
            raise

    def finish(self, result: dict[str, object]) -> None:
        pending, self.pending = self.pending, None
        self.timer.stop()
        if pending is None:
            return
        if (
            pending.action.name in ("open_example", "analyze_case")
            and result.get("status") == "completed"
            and self.window.pages.currentIndex() == 2
        ):
            self.window.navigate(5)
        self.activity.emit(pending.action.name, result)
        if not pending.future.done():
            pending.future.set_result(result)

    @Slot(object, object)
    def dispatch(self, action: object, future: object) -> None:
        if not isinstance(action, AppAction) or not isinstance(future, Future):
            return
        if future.cancelled():
            return
        if self.pending is not None or self.window.controller.busy:
            future.set_result(
                {"status": "busy", "message": "An application operation is already running."}
            )
            return
        self.pending = Pending(action, future, time.monotonic())
        self.activity.emit(action.name, {"status": "running"})
        try:
            self._dispatch(action)
        except Exception:  # noqa: BLE001 -- optional action boundary must finish its future safely.
            self.finish({"status": "failed", "code": "APP_ACTION_UNAVAILABLE"})
            return
        if self.pending is not None:
            self.timer.start()

    def _dispatch(self, action: AppAction) -> None:
        window, controller = self.window, self.window.controller
        view = window.case_view
        pending = self.pending
        assert pending is not None
        if action.name in ("get_app_state", "read_findings"):
            page = action.page or (view.page_index * 25 + 1)
            if view.analysis is not None and (page - 1) * 20 >= max(1, view.total_findings):
                self.finish({"status": "refused", "code": "FINDINGS_PAGE_UNAVAILABLE"})
                return
            source_page = (page - 1) * 20 // 500
            if view.analysis is not None and view.page_index != source_page:
                view.load_page(source_page)
            else:
                self.finish({"status": "completed", "application": self.snapshot(page)})
        elif action.name == "navigate":
            if action.screen is None:
                raise ValueError("A known screen is required")
            window.navigate(window.destinations.index(action.screen))
            self.finish({"status": "completed", "screen": action.screen})
        elif action.name == "open_example":
            window.open_example()
        elif action.name == "choose_case":
            window.choose_case()
            if not controller.busy:
                self.finish({"status": "cancelled", "code": "NO_CASE_CHOSEN"})
        elif action.name == "select_finding":
            entry = self.references.get(action.finding_ref or "")
            if entry is None or entry[0] != self.revision():
                self.finish({"status": "refused", "code": "FINDING_CONTEXT_CHANGED"})
            elif view.page_index != entry[1]:
                view.load_page(entry[1])
            else:
                self.select(action)
        elif action.name == "run_preflight":
            pending.operation = "doctor"
            controller.submit("doctor", {})
        elif action.name == "collect_evidence":
            pending.operation = "collect"
            controller.submit("collect", {"minutes": action.minutes or 10})
        elif action.name == "analyze_case":
            if controller.last_bundle is None:
                self.finish({"status": "refused", "code": "NO_COLLECTED_CASE"})
            else:
                pending.operation = "analyze"
                controller.analyze_collected()
        elif action.name == "export_report":
            if view.analysis is None or view.stale:
                self.finish({"status": "refused", "code": "OPEN_OR_ANALYZE_A_CASE_FIRST"})
            else:
                from wfdiag.gui.controller import default_work_root

                root = controller.root or default_work_root()
                output = root / f"assistant-report-{uuid4()}.html"
                pending.operation = "report"
                self.artifacts.append(output)
                controller.report_source(
                    lambda source: controller.submit(
                        "report",
                        {
                            "analysis": str(source),
                            "mode": action.report_mode or "share",
                            "out": str(output),
                        },
                    )
                )
        elif action.name == "prepare_proposal":
            finding = view.selected()
            if (
                view.path is None
                or view.analysis is None
                or view.stale
                or view.synthetic
                or finding is None
                or not finding.proposal_eligible
                or view.analysis.intent is None
            ):
                self.finish({"status": "refused", "code": "ENGINE_PROPOSAL_NOT_ELIGIBLE"})
            else:
                from wfdiag.gui.controller import default_work_root

                root = controller.root or default_work_root()
                output = root / f"assistant-proposal-{uuid4()}.json"
                self.artifacts.append(output)
                pending.operation = "propose"
                controller.submit(
                    "propose",
                    {
                        "analysis": str(view.path),
                        "finding_id": finding.finding_id,
                        "out": str(output),
                    },
                    intent=view.analysis.intent,
                )
        elif action.name == "compare_cases":
            if window.before_path is None or window.after_path is None:
                window.navigate(3)
                self.finish(
                    {
                        "status": "needs_input",
                        "message": "Choose Before and After analyses in Compare, then ask me to compare them.",
                    }
                )
            else:
                pending.operation = "compare"
                window.run_comparison()

    def select(self, action: AppAction) -> None:
        entry = self.references.get(action.finding_ref or "")
        view = self.window.case_view
        source = view.proxy.sourceModel()
        if entry is None or source is None or entry[0] != self.revision():
            raise ValueError("Finding context changed")
        from wfdiag.gui.read_models import FindingsModel

        if not isinstance(source, FindingsModel):
            raise TypeError("No findings model")
        for row in range(source.rowCount()):
            finding = source.finding(row)
            if finding is not None and finding.finding_id == entry[2]:
                view.search.clear()
                view.proxy.setFilterFixedString("")
                view.table.setCurrentIndex(view.proxy.mapFromSource(source.index(row, 0)))
                self.window.navigate(2)
                self.finish({"status": "completed", "selected_finding": action.finding_ref})
                return
        raise ValueError("Finding not available")

    @Slot(object, object)
    def completed(self, request: object, result: object) -> None:
        if self.pending is not None:
            self.pending.result = result

    @Slot(str, int)
    def failed(self, reason: str, code: int) -> None:
        if self.pending is not None:
            self.pending.error, self.pending.return_code = reason, code

    @Slot(bool)
    def cancelled(self, confirmed: bool) -> None:
        if self.pending is not None:
            self.pending.error = "CANCELLED"

    @Slot()
    def poll(self) -> None:
        pending = self.pending
        if pending is None:
            self.timer.stop()
            return
        if time.monotonic() - pending.started > 420:
            self.window.controller.cancel()
            self.finish({"status": "failed", "code": "APP_ACTION_TIMEOUT"})
            return
        if self.window.controller.busy:
            return
        if pending.future.cancelled():
            self.finish({"status": "cancelled"})
        elif pending.error:
            self.finish(
                {"status": "failed", "code": pending.error, "exit_code": pending.return_code}
            )
        elif pending.action.name == "select_finding":
            try:
                self.select(pending.action)
            except (ValueError, TypeError):
                self.finish({"status": "refused", "code": "FINDING_CONTEXT_CHANGED"})
        elif pending.operation and pending.result is None:
            self.finish({"status": "failed", "code": "APP_OPERATION_NOT_COMPLETED"})
        else:
            result: dict[str, object] = {
                "status": "completed",
                "application": self.snapshot(pending.action.page),
            }
            value = pending.result
            if isinstance(value, DoctorReport):
                result.update(
                    {
                        "eligible_target": value.eligible_target,
                        "architecture": value.host.architecture,
                        "capabilities": {c.name: c.state for c in value.capabilities},
                    }
                )
            elif isinstance(value, Manifest):
                result["completeness"] = value.completeness.value
            elif isinstance(value, Comparison):
                result["observation_change"] = value.observation_change
            elif isinstance(value, Proposal):
                result["proposal_executable"] = False
            self.finish(result)

    @Slot()
    def cancel(self) -> None:
        if self.pending is not None:
            if self.pending.operation and self.window.controller.busy:
                self.window.controller.cancel()
            self.finish({"status": "cancelled"})
