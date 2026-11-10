"""Real GUI/worker/services using synthetic evidence and explicit privacy doubles."""

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from wfdiag.gui import controller, jobs
from wfdiag.gui.main_window import MainWindow

ROOT = Path(__file__).parents[2]
BOOTSTRAP = """from wfdiag.storage import private_output as p
from wfdiag.services import desktop_worker as w
p.create_private_directory=lambda path:path.mkdir()
p.verify_private_directory=lambda path:None
w.verify_private_directory=lambda path:None
from wfdiag.cli import main
raise SystemExit(main())
"""


@pytest.fixture
def working_window(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MainWindow]:
    # These doubles exercise GUI/process wiring, never Windows DACL acceptance.
    def prepare(root: Path) -> Path:
        root.mkdir(exist_ok=True)
        return root

    monkeypatch.setattr(controller, "default_work_root", lambda: tmp_path / "private-work-double")
    monkeypatch.setattr(controller, "prepare_work_root", prepare)
    monkeypatch.setattr(jobs, "create_private_directory", lambda path: path.mkdir())
    monkeypatch.setattr(jobs, "engine_command", lambda: (sys.executable, ["-I", "-c", BOOTSTRAP]))
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    yield window
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    window.close()


def test_real_analyze_report_and_compare_bind_validated_results(
    working_window: MainWindow, qtbot: QtBot, tmp_path: Path
) -> None:
    window = working_window
    window.controller.analyze_bundle(ROOT / "examples/synthetic-case")
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    view = window.case_view
    assert view.analysis is not None and view.path is not None, window.job_status.text()
    assert window.pages.currentIndex() == 2 and view.table.model().rowCount() > 0
    assert view.share_button.isEnabled() and not window.example_open
    path = view.path
    output = tmp_path / "share.json"
    window.controller.submit("report", {"analysis": str(path), "mode": "share", "out": str(output)})
    assert not view.share_button.isEnabled() and not view.proposal_button.isEnabled()
    view.table.selectRow(0)
    assert not view.proposal_button.isEnabled()
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert output.exists() and "Report exported" in window.job_status.text()
    window.controller.submit("compare", {"before": str(path), "after": str(path)})
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert "unchanged" in window.comparison_result.toPlainText()
    assert "does not prove repair" in window.comparison_result.toPlainText()
    assert "Repair is not established" in window.job_status.text()


@pytest.mark.parametrize("mode", ["share", "full"])
@pytest.mark.parametrize("format", ["json", "html"])
def test_indexed_last_page_exports_complete_original_case_via_real_worker(
    working_window: MainWindow, qtbot: QtBot, tmp_path: Path, monkeypatch, mode, format
) -> None:
    from wfdiag.reporting.share import ShareReport
    from wfdiag.storage import analysis_index
    from wfdiag.storage.records import read_analysis, read_record

    full = read_analysis(ROOT / "examples/expected-analysis.json")
    findings = tuple(
        full.findings[0].model_copy(update={"finding_id": f"F{i}"}) for i in range(1001)
    )
    path = tmp_path / "analysis.json"
    path.write_text(
        full.model_copy(update={"findings": findings}).model_dump_json(), encoding="utf-8"
    )
    monkeypatch.setattr(analysis_index, "INDEX_THRESHOLD_BYTES", 1)
    window = working_window
    window.controller.open_analysis(path)
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    view = window.case_view
    assert view.result_index is not None and view.total_findings == 1001
    view.load_page(2)
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert len(view.analysis.findings) == 1 and view.selected().finding_id == "F1000"
    original_bytes = path.read_bytes()
    output = tmp_path / ("whole-" + mode + "." + format)
    window.controller.submit(
        "report", {"analysis": str(view.path), "mode": mode, "out": str(output)}
    )
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert output.exists(), window.job_status.text()
    if format == "html":
        body = output.read_text(encoding="utf-8")
        assert body.count('<h2 id="finding-') == 1001
        if mode == "share":
            assert full.intent.application_path not in body and full.run_id not in body
    elif mode == "share":
        report = read_record(output, ShareReport, byte_limit=8 * 1024 * 1024)
        assert len(report.findings) == 1001
    else:
        report = read_analysis(output)
        assert len(report.findings) == 1001
        assert report == full.model_copy(update={"findings": findings})
    assert path.read_bytes() == original_bytes
    assert view.total_findings == 1001 and len(view.analysis.findings) == 1
    assert "Report exported" in window.job_status.text()


def test_worker_refusal_keeps_existing_findings_and_intent(
    working_window: MainWindow, qtbot: QtBot, tmp_path: Path
) -> None:
    window = working_window
    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    original = window.case_view.analysis
    window.intent_form.application.setText(r"C:\Training\Unchanged.exe")
    window.controller.submit(
        "report",
        {
            "analysis": str(tmp_path / "missing.json"),
            "mode": "share",
            "out": str(tmp_path / "new.json"),
        },
    )
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert "refused" in window.job_status.text()
    assert window.case_view.analysis is original
    assert window.intent_form.application.text() == r"C:\Training\Unchanged.exe"
    assert not (tmp_path / "new.json").exists()


def test_actual_worker_cancel_never_binds_completion(
    working_window: MainWindow, qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = working_window
    bootstrap = BOOTSTRAP.replace(
        "from wfdiag.cli import main",
        """import time
original=w.operations.execute
def delayed(request,cancellation,progress):
    for _ in range(500):
        cancellation.check()
        time.sleep(0.01)
    return original(request,cancellation,progress)
w.operations.execute=delayed
from wfdiag.cli import main""",
    )
    monkeypatch.setattr(jobs, "engine_command", lambda: (sys.executable, ["-I", "-c", bootstrap]))
    output = tmp_path / "never.json"
    window.controller.submit(
        "report",
        {
            "analysis": str(ROOT / "examples/expected-analysis.json"),
            "mode": "share",
            "out": str(output),
        },
    )
    qtbot.waitUntil(
        lambda: window.controller.jobs is not None and window.controller.jobs.busy, timeout=10000
    )
    window.controller.cancel()
    assert "Cancel requested" in window.job_status.text()
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert "Cancelled" in window.job_status.text()
    assert not output.exists() and window.case_view.analysis is None


def test_collect_worker_assembles_fixture_bundle_then_gui_analyzes_it(
    working_window: MainWindow, qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Trusted test bootstrap substitutes native records and DACL handling. The
    # shipped resource runner and actual Windows collection remain unvalidated.
    fixture_capture = f"""import sys
sys.path.insert(0, {str(ROOT)!r})
from tests.unit.test_capture import HOST,FakeResources
from wfdiag.collectors import capture as c
c.create_private_directory=lambda path:path.mkdir()
def fixture_collect(path,minutes,cancellation,progress):
    return c.collect_case(path,minutes,cancellation,progress,host=HOST,runner=FakeResources(),mappings={{}})
c.collect_native_case=fixture_collect
"""
    bootstrap = BOOTSTRAP.replace(
        "from wfdiag.cli import main", fixture_capture + "\nfrom wfdiag.cli import main"
    )
    monkeypatch.setattr(jobs, "engine_command", lambda: (sys.executable, ["-I", "-c", bootstrap]))
    window = working_window
    assert window.collection_minutes.value() == 10
    window.controller.submit("collect", {"minutes": window.collection_minutes.value()})
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert window.controller.last_bundle is not None, window.job_status.text()
    assert window.controller.last_bundle.is_dir()
    assert not window.controller.last_bundle.suffix
    assert window.analyze_collected_button.isEnabled() and window.case_view.analysis is None
    window.controller.analyze_collected()
    qtbot.waitUntil(lambda: not window.controller.busy, timeout=15000)
    assert window.case_view.analysis is not None and window.case_view.path is not None
    assert window.pages.currentIndex() == 2 and not window.case_view.stale
