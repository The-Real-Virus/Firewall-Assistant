"""Missing engine refuses a job before storage or child execution; explicit UI repair path."""

from wfdiag.gui import controller as module
from wfdiag.gui.installation import EngineInstallationUnavailable
from wfdiag.gui.jobs import DesktopJobs
from wfdiag.gui.main_window import MainWindow


def test_engine_failure_preserves_case_and_never_starts_job(qtbot, tmp_path, monkeypatch):
    window = MainWindow()
    qtbot.addWidget(window)
    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    previous = window.case_view.analysis
    root = tmp_path / "not-created"
    window.controller.root = root

    def unavailable():
        raise EngineInstallationUnavailable()

    monkeypatch.setattr(module, "verify_frozen_installation", unavailable)
    window.controller.submit("doctor", {})
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert "Restore the complete matching" in window.job_status.text()
    assert window.controller.jobs is None and not root.exists()
    assert window.case_view.analysis is previous
    assert window.ai_destination.view is None
    window.close()


def test_explicit_log_cleanup_is_bounded_to_idle_memory(qtbot, tmp_path):
    window = MainWindow()
    qtbot.addWidget(window)
    jobs = DesktopJobs(tmp_path, window.controller)
    window.controller.jobs = jobs
    jobs.stderr.extend(b"invented sensitive stderr")
    jobs.stderr_truncated = True
    keep = tmp_path / "keep.txt"
    keep.write_text("invented evidence", encoding="utf-8")
    window.controller.busy = True
    window.settings_view.clear_logs()
    assert jobs.stderr and "Wait" in window.settings_view.save_status.text()
    window.controller.busy = False
    window.settings_view.clear_logs()
    assert not jobs.stderr and not jobs.stderr_truncated
    assert keep.read_text("utf-8") == "invented evidence"
    assert window.preferences.value.recent == ()
    window.close()
