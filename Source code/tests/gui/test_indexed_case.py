"""Source indexed-case journeys, explicit synthetic data and no native startup."""

import json
import threading
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

import pytest
from PySide6.QtCore import QTimer

from wfdiag.contracts.desktop_job import CompletedEvent, decode_request
from wfdiag.contracts.models import Analysis
from wfdiag.gui.jobs import DesktopJobs, validate_result
from wfdiag.gui.main_window import MainWindow
from wfdiag.storage import analysis_index
from wfdiag.storage.analysis_index import open_analysis_index
from wfdiag.version import __version__


def indexed_case(tmp_path: Path):
    analysis = Analysis.model_validate_json(
        files("wfdiag").joinpath("gui/resources/synthetic-analysis.json").read_bytes()
    )
    first = analysis.findings[0]
    findings = tuple(first.model_copy(update={"finding_id": f"F{i}"}) for i in range(1001))
    path = tmp_path / "analysis.json"
    path.write_text(
        analysis.model_copy(update={"findings": findings}).model_dump_json(), encoding="utf-8"
    )
    return open_analysis_index(path), path


def test_page_io_runs_off_gui_with_old_page_visible_until_completion(qtbot, tmp_path, monkeypatch):
    index, path = indexed_case(tmp_path)
    window = MainWindow()
    qtbot.addWidget(window)
    window.controller.bind(index, path)
    view = window.case_view
    assert view.total_findings == 1001 and view.selected().finding_id == "F0"
    assert len(view.analysis.findings) == 500
    original = index.read_page
    entered, release = threading.Event(), threading.Event()
    threads = []

    def delayed(page):
        threads.append(threading.get_ident())
        entered.set()
        assert release.wait(3), "GUI did not remain responsive"
        return original(page)

    monkeypatch.setattr(index, "read_page", delayed)
    main_thread = threading.get_ident()
    view.load_page(2)
    assert window.controller.busy and view.selected().finding_id == "F0"
    qtbot.waitUntil(entered.is_set)
    pulses = []
    QTimer.singleShot(10, lambda: (pulses.append(True), release.set()))
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert pulses and threads == [threads[0]] and threads[0] != main_thread
    assert view.page_index == 2 and view.selected().finding_id == "F1000"
    assert view.proxy.rowCount() == 1 and "of 1001" in view.page_label.text()
    assert not view.next_page.isEnabled() and view.previous_page.isEnabled()
    window.close()
    with pytest.raises(ValueError, match="closed"):
        original(0)


def test_page_failure_preserves_last_validated_page(qtbot, tmp_path):
    index, path = indexed_case(tmp_path)
    window = MainWindow()
    qtbot.addWidget(window)
    window.controller.bind(index, path)
    before = window.case_view.analysis
    index.close()
    window.case_view.load_page(1)
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert window.case_view.analysis is before and window.case_view.page_index == 0
    assert "Failed" in window.job_status.text()
    window.close()


def test_replacing_case_releases_held_index(qtbot, tmp_path):
    index, path = indexed_case(tmp_path)
    window = MainWindow()
    qtbot.addWidget(window)
    window.controller.bind(index, path)
    window.controller.bind(index.first_page, None, synthetic=True)
    assert window.case_view.result_index is None
    with pytest.raises(ValueError, match="closed"):
        index.read_page(0)
    path.unlink()
    window.close()


def test_cancelled_local_index_load_releases_unbound_file(qtbot, tmp_path):
    index, _ = indexed_case(tmp_path)
    window = MainWindow()
    qtbot.addWidget(window)
    release = threading.Event()
    called = []

    def load():
        assert release.wait(3)
        return index

    window.controller.run_local(load, called.append)
    window.controller.cancel()
    release.set()
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert not called and window.case_view.analysis is None
    with pytest.raises(ValueError, match="closed"):
        index.read_page(0)
    window.close()


@pytest.mark.parametrize("cancelled", [False, True])
def test_stale_or_cancelled_worker_output_releases_index(qtbot, tmp_path, cancelled):
    index, path = indexed_case(tmp_path)
    jobs = DesktopJobs(tmp_path)
    request = decode_request(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": str(uuid4()),
                "operation": "analyze",
                "expected_engine_version": __version__,
                "parameters": {"bundle": str(tmp_path), "out": str(path)},
            }
        ).encode()
    )
    if cancelled:
        jobs.request = request
        jobs.cancel_requested = True
    jobs._checked(request.job_id, index, "")
    with pytest.raises(ValueError, match="closed"):
        index.read_page(0)


def test_worker_index_keeps_version_and_terminal_state_checks(qtbot, tmp_path, monkeypatch):
    index, path = indexed_case(tmp_path)
    index.close()
    monkeypatch.setattr(analysis_index, "INDEX_THRESHOLD_BYTES", 1)
    request = decode_request(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": str(uuid4()),
                "operation": "analyze",
                "expected_engine_version": __version__,
                "parameters": {"bundle": str(tmp_path), "out": str(path)},
            }
        ).encode()
    )
    terminal = CompletedEvent.model_validate_json(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": request.job_id,
                "sequence": 2,
                "type": "completed",
                "payload": {"output": str(path), "completeness": "complete", "exit_code": 0},
            }
        )
    )
    result = validate_result(request, terminal, 0)
    try:
        assert result.count == 1001 and len(result.first_page.findings) == 500
    finally:
        result.close()
    raw = json.loads(path.read_bytes())
    raw["engine_version"] = "unrelated-version"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="version"):
        validate_result(request, terminal, 0)
    path.unlink()
