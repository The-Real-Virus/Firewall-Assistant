"""Actual QProcess/service round trip with explicit directory-privacy doubles."""

import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from pytestqt.qtbot import QtBot

from wfdiag.contracts.desktop_job import decode_request
from wfdiag.gui import jobs
from wfdiag.reporting.share import ShareReport
from wfdiag.version import __version__

ROOT = Path(__file__).parents[2]
BOOTSTRAP = "from wfdiag.services import desktop_worker as w; w.verify_private_directory=lambda path:None; from wfdiag.cli import main; raise SystemExit(main())"


def test_qprocess_roundtrip_loads_real_share_output(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "jobs"
    root.mkdir()

    def create(path: Path) -> None:
        path.mkdir()

    monkeypatch.setattr(jobs, "create_private_directory", create)
    monkeypatch.setattr(jobs, "engine_command", lambda: (sys.executable, ["-I", "-c", BOOTSTRAP]))
    controller = jobs.DesktopJobs(root)
    output = tmp_path / "share.json"
    request = decode_request(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": str(uuid4()),
                "operation": "report",
                "expected_engine_version": __version__,
                "parameters": {
                    "analysis": str(ROOT / "examples/expected-analysis.json"),
                    "mode": "share",
                    "out": str(output),
                },
            }
        ).encode()
    )
    failures = []
    controller.failed.connect(lambda reason, code: failures.append((reason, code)))
    with qtbot.waitSignal(controller.completed, timeout=10000) as signal:
        controller.start(request)
    assert failures == [] and signal.args[0] == request
    assert isinstance(signal.args[1], ShareReport)
    assert output.exists() and not controller.busy


def test_qprocess_failure_never_emits_completion(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "jobs"
    root.mkdir()
    monkeypatch.setattr(jobs, "create_private_directory", lambda path: path.mkdir())
    monkeypatch.setattr(jobs, "engine_command", lambda: (sys.executable, ["-I", "-c", BOOTSTRAP]))
    controller = jobs.DesktopJobs(root)
    output = tmp_path / "new.json"
    request = decode_request(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": str(uuid4()),
                "operation": "report",
                "expected_engine_version": __version__,
                "parameters": {
                    "analysis": str(tmp_path / "missing.json"),
                    "mode": "share",
                    "out": str(output),
                },
            }
        ).encode()
    )
    completed = []
    controller.completed.connect(lambda *args: completed.append(args))
    with qtbot.waitSignal(controller.failed, timeout=10000) as signal:
        controller.start(request)
    assert signal.args[1] == 2 and not completed
    assert not output.exists() and not controller.busy
