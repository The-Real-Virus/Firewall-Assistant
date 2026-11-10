"""Generated output validation must keep actual limits and release held resources."""

import json
from pathlib import Path
from uuid import uuid4

import pytest

from wfdiag.contracts.desktop_job import CompletedEvent, decode_request
from wfdiag.gui import jobs
from wfdiag.reporting.render import render_report
from wfdiag.reporting.share import make_share_report
from wfdiag.storage import analysis_index
from wfdiag.storage.records import read_analysis
from wfdiag.version import __version__

ROOT = Path(__file__).parents[2]
HEADER = b"<!doctype html><meta content=\"default-src 'none'\">"


def validate(path: Path, mode="share"):
    request = decode_request(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": str(uuid4()),
                "operation": "report",
                "expected_engine_version": __version__,
                "parameters": {
                    "analysis": str(ROOT / "examples/expected-analysis.json"),
                    "mode": mode,
                    "out": str(path),
                },
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
    return jobs.validate_result(request, terminal, 0)


def test_streamed_html_at_exact_budget_releases_handle(tmp_path, monkeypatch):
    path = tmp_path / "report.html"
    body = HEADER + b"x" * 131072
    path.write_bytes(body)
    monkeypatch.setattr(jobs, "MAX_HTML_REPORT_BYTES", len(body))
    assert validate(path) == path
    path.unlink()


@pytest.mark.parametrize("body", [b"", b"<html>missing template</html>", b"<!doctype html>"])
def test_invalid_html_never_becomes_completed_output(tmp_path, body):
    path = tmp_path / "bad.html"
    path.write_bytes(body)
    with pytest.raises(ValueError):
        validate(path)
    path.unlink()


@pytest.mark.parametrize("understated_size", [False, True])
def test_html_actual_byte_cap_cannot_be_bypassed_by_initial_size(
    tmp_path, monkeypatch, understated_size
):
    from types import SimpleNamespace

    path = tmp_path / "oversized.html"
    path.write_bytes(HEADER + b"x" * 131072)
    monkeypatch.setattr(jobs, "MAX_HTML_REPORT_BYTES", 65536)
    if understated_size:
        original = jobs.os.fstat

        def fake_size(fd):
            info = original(fd)
            return SimpleNamespace(
                st_size=1,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_mtime_ns=info.st_mtime_ns,
                st_ctime_ns=info.st_ctime_ns,
            )

        monkeypatch.setattr(jobs.os, "fstat", fake_size)
    with pytest.raises(ValueError, match="budget"):
        validate(path)
    path.unlink()


def test_large_json_validation_returns_original_paths_and_closes_indexes(tmp_path, monkeypatch):
    analysis = read_analysis(ROOT / "examples/expected-analysis.json")
    path = tmp_path / "full.json"
    path.write_bytes(render_report(analysis, mode="full", format="json"))
    monkeypatch.setattr(analysis_index, "INDEX_THRESHOLD_BYTES", 1)
    assert validate(path, "full") == path
    path.unlink()  # Windows refuses this if the validator leaked its held index.
    path = tmp_path / "share.json"
    raw = make_share_report(analysis).model_dump(mode="json")
    path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(jobs, "MAX_INLINE_REPORT_BYTES", 1)
    assert validate(path) == path
    path.unlink()
    raw["findings"][-1]["proposal_eligible"] = "false"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        validate(path)
    path.unlink()
