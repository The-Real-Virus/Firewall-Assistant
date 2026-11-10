"""Service round trips with a storage double, never Windows ACL acceptance."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from wfdiag.cli import main
from wfdiag.contracts.models import Analysis, Proposal
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.services import operations
from wfdiag.services.cancellation import CancellationToken
from wfdiag.storage import private_output
from wfdiag.storage.records import read_analysis

EXAMPLES = Path(__file__).parents[2] / "examples"


@pytest.fixture
def storage_double(monkeypatch: pytest.MonkeyPatch) -> None:
    # This exercises orchestration and failure semantics, not native confidentiality.
    def create(path: Path) -> None:
        path.mkdir()

    monkeypatch.setattr(private_output, "create_private_directory", create)
    monkeypatch.setattr(private_output, "verify_private_directory", lambda path: None)


def analyze_arguments(destination: Path, bundle: Path | None = None) -> list[str]:
    return [
        "analyze",
        "--bundle",
        str(bundle or EXAMPLES / "synthetic-case"),
        "--intent",
        str(EXAMPLES / "intent-synthetic-confirmed.json"),
        "--out",
        str(destination),
    ]


def test_shared_cli_analyze_report_propose_compare_with_storage_double(
    tmp_path: Path, storage_double: None
) -> None:
    result = tmp_path / "analysis Ω"
    assert main(analyze_arguments(result)) == 0
    assert list(result.iterdir()) == [result / "analysis.json"]
    analysis = read_analysis(result)
    assert analysis.findings[0].category.value == "DEFAULT_BLOCK"
    assert analysis.findings[0].proposal_eligible
    assert (
        main(
            [
                "report",
                "--analysis",
                str(result),
                "--mode",
                "share",
                "--out",
                str(tmp_path / "share.html"),
            ]
        )
        == 0
    )
    assert b"Review before sharing" in (tmp_path / "share.html").read_bytes()
    assert (
        main(
            [
                "report",
                "--analysis",
                str(result),
                "--mode",
                "full",
                "--out",
                str(tmp_path / "full.json"),
            ]
        )
        == 0
    )
    assert Analysis.model_validate_json((tmp_path / "full.json").read_bytes()) == analysis
    proposal = tmp_path / "proposal.json"
    assert (
        main(
            [
                "propose",
                "--analysis",
                str(result),
                "--intent",
                str(EXAMPLES / "intent-synthetic-confirmed.json"),
                "--finding-id",
                analysis.findings[0].finding_id,
                "--out",
                str(proposal),
            ]
        )
        == 0
    )
    assert Proposal.model_validate_json(proposal.read_bytes()).executable is False
    assert (
        main(
            [
                "compare",
                "--before",
                str(result),
                "--after",
                str(result),
                "--out",
                str(tmp_path / "comparison.json"),
            ]
        )
        == 0
    )
    comparison = json.loads((tmp_path / "comparison.json").read_bytes())
    assert comparison["observation_change"] == "unchanged"
    assert comparison["repair_status"] == "not_established"


def test_incomplete_sources_produce_usable_incomplete_analysis_and_exit5(
    tmp_path: Path, storage_double: None
) -> None:
    bundle = tmp_path / "partial case"
    shutil.copytree(EXAMPLES / "synthetic-case", bundle)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["completeness"] = "incomplete"
    next(s for s in manifest["sources"] if s["source"] == "rules")["state"] = "access_denied"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = tmp_path / "partial analysis"
    assert main(analyze_arguments(result, bundle)) == 5
    analysis = read_analysis(result)
    assert analysis.completeness.value == "incomplete"
    assert all(not finding.proposal_eligible for finding in analysis.findings)
    assert not (result / ".incomplete").exists()


def test_existing_analysis_is_preserved(tmp_path: Path, storage_double: None) -> None:
    result = tmp_path / "existing"
    result.mkdir()
    original = result / "keep.txt"
    original.write_text("original", encoding="utf-8")
    assert main(analyze_arguments(result)) == 2
    assert original.read_text(encoding="utf-8") == "original"
    assert list(result.iterdir()) == [original]


def test_output_failure_retains_marker_and_is_never_read_as_completed(
    tmp_path: Path, storage_double: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("synthetic interrupted final write")

    monkeypatch.setattr(operations, "write_new_chunks", fail)
    result = tmp_path / "failed analysis"
    assert main(analyze_arguments(result)) == 6
    assert (result / ".incomplete").exists()
    assert not (result / "analysis.json").exists()
    with pytest.raises(DiagnosticError, match="incomplete"):
        read_analysis(result)


def test_cancel_after_write_keeps_result_uncommitted(
    tmp_path: Path, storage_double: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wfdiag.contracts.desktop_job import decode_request
    from wfdiag.version import __version__

    token = CancellationToken()
    original = operations.write_new_chunks

    def cancel_after(path: Path, content: object, **kwargs: int) -> None:
        original(path, content, **kwargs)
        token.request()

    monkeypatch.setattr(operations, "write_new_chunks", cancel_after)
    result = tmp_path / "cancelled analysis"
    request = decode_request(
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": "synthetic-job",
                "operation": "analyze",
                "expected_engine_version": __version__,
                "parameters": {
                    "bundle": str(EXAMPLES / "synthetic-case"),
                    "intent": str(EXAMPLES / "intent-synthetic-confirmed.json"),
                    "out": str(result),
                },
            }
        ).encode()
    )
    with pytest.raises(DiagnosticError) as caught:
        operations.execute(request, token, lambda *args: None)
    assert caught.value.code == ExitCode.INCOMPLETE
    assert (result / "analysis.json").exists() and (result / ".incomplete").exists()
    with pytest.raises(DiagnosticError):
        read_analysis(result)
    with pytest.raises(DiagnosticError):
        read_analysis(result / "analysis.json")


def test_full_export_fails_closed_when_private_destination_cannot_be_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def unavailable(path: Path) -> None:
        raise PermissionError("synthetic private path detail")

    monkeypatch.setattr(private_output, "verify_private_directory", unavailable)
    target = tmp_path / "private.html"
    assert (
        main(
            [
                "report",
                "--analysis",
                str(EXAMPLES / "expected-analysis.json"),
                "--mode",
                "full",
                "--out",
                str(target),
            ]
        )
        == 4
    )
    assert not target.exists()
    captured = capsys.readouterr()
    assert not captured.out
    assert "synthetic private path detail" not in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "command",
    [
        ["analyze", "--bundle", "missing"],
        ["report", "--analysis", "missing", "--mode", "share"],
        ["compare", "--before", "missing", "--after", "missing"],
    ],
)
def test_invalid_inputs_do_not_create_outputs(command: list[str], tmp_path: Path) -> None:
    destination = tmp_path / "new.json"
    assert main([*command, "--out", str(destination)]) == 2
    assert not list(tmp_path.iterdir())


def add_optional_log(
    tmp_path: Path, *, body: bytes, state: str = "complete", events: bool = True, count: int = 1
) -> Path:
    bundle = tmp_path / "case with optional text"
    shutil.copytree(EXAMPLES / "synthetic-case", bundle)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    (bundle / "firewall-log.txt").write_bytes(body)
    manifest["files"].append(
        {
            "filename": "firewall-log.txt",
            "byte_length": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    )
    manifest["sources"].append(
        {
            "source": "firewall-log",
            "state": state,
            "window_start_utc": None,
            "window_end_utc": None,
            "records": count,
            "warnings": [],
        }
    )
    if not events:
        (bundle / "events.ndjson").write_bytes(b"")
        next(f for f in manifest["files"] if f["filename"] == "events.ndjson").update(
            byte_length=0, sha256=hashlib.sha256(b"").hexdigest()
        )
        next(s for s in manifest["sources"] if s["source"] == "events").update(
            state="empty", records=0
        )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return bundle


TEXT_HEADER = b"#Fields: date time action protocol src-ip dst-ip src-port dst-port\n"
TEXT_RECORD = b"2026-11-01 00:05:00 DROP TCP 192.168.56.20 192.168.56.10 51000 8765\n"


def test_text_log_alone_never_establishes_application_identity_or_proposal(
    tmp_path: Path, storage_double: None
) -> None:
    bundle = add_optional_log(tmp_path, body=TEXT_HEADER + TEXT_RECORD, events=False)
    result = tmp_path / "text-only analysis"
    assert main(analyze_arguments(result, bundle)) == 0
    analysis = read_analysis(result)
    assert analysis.firewall_log is not None
    (observation,) = analysis.firewall_log.observations
    assert observation.timestamp_utc is None and observation.time_basis == "unknown"
    assert not analysis.firewall_log.application_identity_available
    assert all(not f.proposal_eligible for f in analysis.findings)
    assert analysis.findings[0].category.value == "NO_RELEVANT_EVENT"


@pytest.mark.parametrize(
    "body,state,count,expected",
    [
        (TEXT_HEADER + TEXT_RECORD.rstrip(b"\n"), "complete", 1, "truncated"),
        (b"", "access_denied", 0, "access_denied"),
        (TEXT_HEADER + TEXT_RECORD, "complete", 0, "error"),
    ],
)
def test_optional_failure_does_not_hide_a_valid_required_event_source(
    tmp_path: Path, storage_double: None, body: bytes, state: str, count: int, expected: str
) -> None:
    bundle = add_optional_log(tmp_path, body=body, state=state, count=count)
    result = tmp_path / "analysis with optional warning"
    assert main(analyze_arguments(result, bundle)) == (5 if expected == "truncated" else 0)
    analysis = read_analysis(result)
    assert analysis.completeness.value == ("incomplete" if expected == "truncated" else "complete")
    assert next(s for s in analysis.sources if s.source == "firewall-log").state.value == expected
    assert analysis.findings[0].relevance.value == "relevant"
