"""Actual GUI/services, with explicit Windows-consent and privacy doubles only."""

import shutil
from pathlib import Path

from tests.gui.test_workflow import working_window as _working_window
from wfdiag.gui import controller

ROOT = Path(__file__).parents[2]
working_window = _working_window


def test_compare_rejects_raw_network_json_before_starting_worker(
    working_window, qtbot, monkeypatch
):
    window = working_window
    monkeypatch.setattr(
        "wfdiag.gui.main_window.QFileDialog.getOpenFileName",
        lambda *_: (str(ROOT / "examples/synthetic-case/network.json"), ""),
    )
    window.choose_comparison("Before")
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert window.before_path is None
    assert "Not a saved analysis" in window.comparison_paths["Before"].text()
    assert "network.json" in window.job_status.text() and "not analysis" in window.job_status.text()
    assert window.controller.jobs is None


def test_compare_accepts_validated_analysis(working_window, qtbot, monkeypatch):
    window = working_window
    path = ROOT / "examples/expected-analysis.json"
    monkeypatch.setattr(
        "wfdiag.gui.main_window.QFileDialog.getOpenFileName", lambda *_: (str(path), "")
    )
    window.choose_comparison("Before")
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert window.before_path == path
    assert "Choose the other analysis" in window.job_status.text()
    window.choose_comparison("After")
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert window.after_path == path
    assert "Both analyses are ready" in window.job_status.text()


def test_general_investigation_hides_technical_connection_fields(working_window):
    form = working_window.intent_form
    assert form.fields.isHidden() and form.value() is None
    form.enabled.setChecked(True)
    assert not form.fields.isHidden()
    assert "website" in form.direction.itemText(0)
    working_window.controller.start_guided()
    assert working_window.job_status.text() == controller.GUIDED_INTENT_ERROR
    form.enabled.setChecked(False)
    assert "General review selected" in working_window.job_status.text()


def test_permission_capture_returns_to_normal_worker_for_analysis(
    working_window, qtbot, monkeypatch
):
    window = working_window
    processes = []

    class Process:
        closed = False

        def poll(self):
            return 0

        def close(self):
            self.closed = True

    def allowed(out, minutes, owner):
        shutil.copytree(ROOT / "examples/synthetic-case", out, dirs_exist_ok=True)
        process = Process()
        processes.append(process)
        return process

    monkeypatch.setattr(controller, "request_collection", allowed)
    window.controller.guided_run = True
    window.controller.collect_with_permission()
    qtbot.waitUntil(
        lambda: window.case_view.analysis is not None and not window.controller.busy, timeout=15000
    )
    assert processes[0].closed
    assert window.controller.permission_process is None
    assert window.case_view.analysis.sources
    assert window.controller.last_bundle.name.startswith("permission-case-")


def test_cancelled_windows_prompt_keeps_previous_case_and_allows_normal_retry(
    working_window, qtbot, monkeypatch
):
    window = working_window
    window.open_example()
    qtbot.waitUntil(lambda: window.case_view.analysis is not None and not window.controller.busy)
    original = window.case_view.analysis

    def declined(*args):
        raise controller.PermissionDeclined()

    monkeypatch.setattr(controller, "request_collection", declined)
    window.controller.collect_with_permission()
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert window.case_view.analysis is original
    assert "cancelled" in window.job_status.text()
    assert window.controller.permission_process is None
    window.controller.analyze_bundle(ROOT / "examples/synthetic-case")
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert window.case_view.path is not None
