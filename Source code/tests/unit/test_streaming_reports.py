"""Actual streamed report semantics, privacy, laziness, cancellation and atomic limits."""

import json
from pathlib import Path

import pytest
from engine_data import Scenario, changed

from wfdiag.contracts.models import Analysis, Event, Finding
from wfdiag.reporting.render import REPORT_BUFFER_BYTES, iter_report_chunks, render_report
from wfdiag.reporting.share import ShareReport
from wfdiag.services.cancellation import CancellationToken, Cancelled
from wfdiag.storage.analysis_json import analysis_json_chunks
from wfdiag.storage.atomic_write import write_new_chunks


def many(analysis: Analysis, count: int = 1001) -> Analysis:
    return changed(
        analysis,
        findings=[
            {**analysis.findings[0].model_dump(mode="json"), "finding_id": f"F{i}"}
            for i in range(count)
        ],
    )


def test_html_first_batch_does_not_dump_the_whole_case(scenario: Scenario, monkeypatch) -> None:
    analysis = many(scenario.analyze())
    visited = []
    original = Finding.model_dump

    def counted(self, *args, **kwargs):
        visited.append(self.finding_id)
        return original(self, *args, **kwargs)

    original_root = Analysis.model_dump

    def guarded(self, *args, **kwargs):
        assert {"findings", "policy_rules", "firewall_log"} <= kwargs.get("exclude", set())
        return original_root(self, *args, **kwargs)

    monkeypatch.setattr(Finding, "model_dump", counted)
    monkeypatch.setattr(Analysis, "model_dump", guarded)
    stream = iter_report_chunks(analysis, mode="full", format="html")
    try:
        first = next(stream)
        assert first.startswith(b"<!doctype html>") and len(first) <= REPORT_BUFFER_BYTES
        assert 0 < len(visited) < len(analysis.findings)
    finally:
        stream.close()


def test_optional_log_arrays_stream_and_reconstruct_exactly(scenario: Scenario) -> None:
    from wfdiag.parsers.firewall_log import parse_firewall_log

    log = parse_firewall_log(
        [
            b"#Fields: date time action protocol src-ip dst-ip src-port dst-port note\n",
            b"2026-11-01 00:05:00 DROP TCP 192.0.2.1 192.0.2.2 51000 443 synthetic\n",
            b"malformed invented row\n",
        ]
    )
    analysis = scenario.analyze()
    raw = analysis.model_dump(mode="json")
    raw["sources"].append(
        {
            "source": "firewall-log",
            "state": "complete",
            "window_start_utc": None,
            "window_end_utc": None,
            "records": 1,
            "warnings": [],
        }
    )
    raw["firewall_log"] = log.model_dump(mode="json")
    analysis = Analysis.model_validate_json(json.dumps(raw))
    for metadata_defaults in (False, True):
        data = b"".join(analysis_json_chunks(analysis, include_metadata_defaults=metadata_defaults))
        assert Analysis.model_validate_json(data) == analysis
    full = render_report(analysis, mode="full", format="json")
    assert Analysis.model_validate_json(full) == analysis
    assert json.loads(full)["schema_version"] == "1.0"


def test_required_unknowns_and_false_eligibility_are_explicit(scenario: Scenario) -> None:
    raw = scenario.analyze().model_dump(mode="json")
    raw["intent"] = None
    for finding in raw["findings"]:
        finding.update(proposal_eligible=False, policy_snapshot_utc=None)
    analysis = Analysis.model_validate_json(json.dumps(raw))
    value = json.loads(render_report(analysis, mode="full", format="json"))
    assert value["schema_version"] == "1.0" and value["intent"] is None
    assert value["findings"][0]["proposal_eligible"] is False
    assert value["findings"][0]["policy_snapshot_utc"] is None
    assert Analysis.model_validate_json(json.dumps(value)) == analysis


@pytest.mark.parametrize("mode", ["share", "full"])
@pytest.mark.parametrize("format", ["html", "json"])
def test_cancelled_stream_never_publishes_output(
    scenario: Scenario, tmp_path: Path, mode, format
) -> None:
    analysis = many(scenario.analyze())
    token = CancellationToken()

    def cancelled_chunks():
        for number, chunk in enumerate(
            iter_report_chunks(analysis, mode=mode, format=format, cancellation=token)
        ):
            yield chunk
            if number == 0:
                token.request()

    path = tmp_path / ("cancelled." + format)
    with pytest.raises(Cancelled):
        write_new_chunks(path, cancelled_chunks())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("mode", ["share", "full"])
@pytest.mark.parametrize("format", ["html", "json"])
def test_actual_output_limit_removes_staging_and_preserves_existing(
    scenario: Scenario, tmp_path: Path, mode, format
) -> None:
    analysis = scenario.analyze()
    path = tmp_path / ("limited." + format)
    with pytest.raises(ValueError, match="budget"):
        write_new_chunks(
            path, iter_report_chunks(analysis, mode=mode, format=format), byte_limit=32
        )
    assert list(tmp_path.iterdir()) == []
    path.write_bytes(b"existing synthetic report")
    with pytest.raises(FileExistsError):
        write_new_chunks(path, iter_report_chunks(analysis, mode=mode, format=format))
    assert path.read_bytes() == b"existing synthetic report"


def test_share_stream_keeps_all_records_and_one_alias_map(scenario: Scenario) -> None:
    analysis = many(scenario.analyze(), 501)
    body = b"".join(iter_report_chunks(analysis, mode="share", format="json"))
    report = ShareReport.model_validate_json(body)
    assert len(report.findings) == 501 and len({f.finding_alias for f in report.findings}) == 501
    assert report.review_required and report.completeness == analysis.completeness
    # These invented findings deliberately refer to the same original observation.
    assert len({f.evidence_aliases for f in report.findings}) == 1
    assert (
        analysis.run_id.encode() not in body
        and analysis.intent.application_path.encode() not in body
    )


def test_event_json_is_prepared_lazily_during_html_render(scenario: Scenario, monkeypatch) -> None:
    analysis = many(scenario.analyze())
    calls = []
    original = Event.model_dump_json

    def counted(self, *args, **kwargs):
        calls.append(self.source_ref)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Event, "model_dump_json", counted)
    stream = iter_report_chunks(analysis, mode="full", format="html")
    try:
        assert not calls
        next(stream)
        assert 0 < len(calls) < len(analysis.findings)
    finally:
        stream.close()
