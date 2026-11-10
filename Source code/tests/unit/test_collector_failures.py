"""Safe actionable collection errors and completed desktop capability reports."""

import json

import pytest

from wfdiag.collectors.failures import (
    FAILURE_MESSAGES,
    CollectorProbeFailure,
    classify_failure,
    exception_failure,
)
from wfdiag.collectors.preflight import doctor
from wfdiag.collectors.process_runner import ProcessResult
from wfdiag.contracts.desktop_job import decode_request
from wfdiag.contracts.enums import Completeness, SourceState
from wfdiag.contracts.models import Host
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.services import desktop_worker, operations
from wfdiag.services.cancellation import CancellationToken
from wfdiag.version import __version__


@pytest.mark.parametrize(
    ("stderr", "code", "state"),
    [
        (
            "PSSecurityException CANARY_PRIVATE_PATH",
            "COLLECTOR_SCRIPT_POLICY_BLOCKED",
            SourceState.ACCESS_DENIED,
        ),
        (
            "UnauthorizedAccessException CANARY",
            "COLLECTOR_ACCESS_DENIED",
            SourceState.ACCESS_DENIED,
        ),
        ("Modules_ModuleNotFound CANARY", "COLLECTOR_DEPENDENCY_MISSING", SourceState.ERROR),
        ("ParserError CANARY", "COLLECTOR_SCRIPT_INVALID", SourceState.ERROR),
        ("CANARY unknown stderr", "COLLECTOR_PROCESS_OR_STREAM_FAILED", SourceState.ERROR),
    ],
)
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_failure_classification_never_returns_private_stderr(stderr, code, state, encoding):
    result = ProcessResult(b"", stderr.encode(encoding), 1, False, False, False, False)
    assert classify_failure(result) == (code, state)
    assert "CANARY" not in FAILURE_MESSAGES[code]


def test_script_policy_failure_keeps_platform_eligible_and_explains_missing_capability():
    facts = Host(
        os="windows",
        edition="Professional",
        build="19045.6466",
        architecture="x64",
        supported_build=False,
        windows_product_type=1,
    )

    def blocked(token):
        raise CollectorProbeFailure("COLLECTOR_SCRIPT_POLICY_BLOCKED")

    report, code = doctor(facts, blocked, CancellationToken())
    assert report.eligible_target and code == ExitCode.ACCESS_DENIED
    assert "Windows blocked" in report.support_note
    assert next(c for c in report.capabilities if c.name == "powershell_51").state == "denied"


@pytest.mark.parametrize(
    "error,expected",
    [
        (PermissionError("CANARY_PRIVATE_PATH"), "COLLECTOR_ACCESS_DENIED"),
        (FileNotFoundError("CANARY_PRIVATE_PATH"), "COLLECTOR_DEPENDENCY_MISSING"),
        (OSError("CANARY_PRIVATE_PATH"), "COLLECTOR_START_FAILED"),
        (ValueError("CANARY_PRIVATE_RECORD"), "COLLECTOR_STREAM_INVALID"),
    ],
)
def test_collector_exception_uses_safe_category_without_private_message(error, expected):
    reason, _ = exception_failure(error)
    assert reason == expected and "CANARY" not in FAILURE_MESSAGES[reason]


def test_desktop_displays_valid_unavailable_report_without_claiming_capability_success(
    tmp_path, monkeypatch
):
    facts = Host(os="linux", edition=None, build=None, architecture="x64", supported_build=False)
    report, code = doctor(facts, lambda token: b"", CancellationToken())
    out = tmp_path / "doctor.json"
    request = decode_request(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": "test-doctor",
                "operation": "doctor",
                "expected_engine_version": __version__,
                "parameters": {"out": str(out)},
            }
        ).encode()
    )

    def run(*args):
        out.write_text(report.model_dump_json(), encoding="utf-8")
        raise DiagnosticError(code, "Capability unavailable")

    monkeypatch.setattr(operations, "execute", run)
    assert (
        desktop_worker.execute_desktop(request, CancellationToken(), lambda *args: None)
        == Completeness.COMPLETE
    )
    assert not json.loads(out.read_text())["eligible_target"]
    out.unlink()
    monkeypatch.setattr(
        operations,
        "execute",
        lambda *args: (_ for _ in ()).throw(DiagnosticError(code, "No report")),
    )
    with pytest.raises(DiagnosticError):
        desktop_worker.execute_desktop(request, CancellationToken(), lambda *args: None)
