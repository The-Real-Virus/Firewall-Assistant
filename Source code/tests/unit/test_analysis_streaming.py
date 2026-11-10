"""Lossless persistence, cancellation and atomic byte caps; no native ACL claim."""

import json
from pathlib import Path

import pytest
from engine_data import Scenario, changed
from pydantic import ValidationError

from wfdiag.contracts.models import Analysis, Event
from wfdiag.errors import DiagnosticError
from wfdiag.parsers.deduplication import iter_event_groups
from wfdiag.services.cancellation import CancellationToken
from wfdiag.storage.analysis_json import analysis_json_chunks
from wfdiag.storage.atomic_write import write_new_chunks
from wfdiag.storage.records import read_analysis


def test_stream_roundtrip_preserves_all_fields_and_uncertainty(
    scenario: Scenario, tmp_path: Path
) -> None:
    scenario.event = changed(
        scenario.event,
        application_raw=r"\Device\Synthetic\Ω.exe",
        pid_value=None,
        unknown_fields={"source-note": "synthetic <markup> Ω"},
        warnings=["UNKNOWN_IDENTITY"],
    )
    scenario.manifest = changed(scenario.manifest, policy_change_observed=None)
    analysis = scenario.analyze()
    before = analysis.model_dump_json()
    destination = tmp_path / "analysis.json"
    write_new_chunks(destination, analysis_json_chunks(analysis))
    assert read_analysis(destination) == analysis
    assert analysis.model_dump_json() == before
    assert analysis.findings[0].proposal_eligible is False
    assert analysis.findings[0].event.pid_value is None
    assert "POLICY_CONTINUITY_UNKNOWN" in analysis.findings[0].refusal_codes


def test_stream_includes_rules_and_actual_false_values(scenario: Scenario) -> None:
    analysis = scenario.analyze()
    data = b"".join(analysis_json_chunks(analysis))
    assert Analysis.model_validate_json(data) == analysis
    assert b'"policy_change_observed":false' in data
    assert b'"policy_rules":' in data


def test_stream_cancelled_mid_write_never_finalizes(scenario: Scenario, tmp_path: Path) -> None:
    analysis = scenario.analyze()
    token = CancellationToken()

    def chunks():
        for index, chunk in enumerate(analysis_json_chunks(analysis, token)):
            yield chunk
            if index == 0:
                token.request()

    with pytest.raises(DiagnosticError):
        write_new_chunks(tmp_path / "cancelled.json", chunks())
    assert list(tmp_path.iterdir()) == []


def test_stream_actual_byte_cap_cleans_staging_and_preserves_existing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="byte budget"):
        write_new_chunks(tmp_path / "new.json", iter((b"12345", b"67890")), byte_limit=9)
    assert list(tmp_path.iterdir()) == []
    path = tmp_path / "existing.json"
    path.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        write_new_chunks(path, (b"new",))
    assert path.read_bytes() == b"original"


def test_dedup_late_provenance_and_conflicting_attempts_are_preserved(scenario: Scenario) -> None:
    first = scenario.event
    second = changed(first, record_id=first.record_id + 1, source_ref="events:second")
    duplicate = changed(first, source_ref="events:late")
    groups = tuple(iter_event_groups((first, second, first, duplicate, duplicate)))
    assert len(groups) == 2
    assert groups[0].event == first
    assert groups[0].source_refs == (first.source_ref, "events:late")
    assert groups[1].event == second


def test_event_metadata_ownership_copy_and_frozen_validation_survive(scenario: Scenario) -> None:
    original = scenario.event
    content = original.model_dump_json()
    value = Event.model_validate_json(content)
    assert value == original and value.model_fields_set == original.model_fields_set
    assert value.model_fields_set is not original.model_fields_set
    copy = value.model_copy(update={"source_ref": "events:copy"})
    assert copy.source_ref == "events:copy" and value.source_ref == original.source_ref
    copy.model_fields_set.discard("provider")
    assert "provider" in value.model_fields_set
    assert Event.model_validate_json(value.model_dump_json(exclude_unset=True)) == value
    with pytest.raises(ValidationError, match="frozen"):
        value.record_id = 42
    with pytest.raises(ValidationError):
        Event.model_validate_json(content.replace('"event_id":5157', '"event_id":true'))


def test_incremental_reader_accepts_property_order_and_escaped_text(
    scenario: Scenario, tmp_path: Path
) -> None:
    analysis = scenario.analyze()
    raw = analysis.model_dump(mode="json")
    finding = raw.pop("findings")
    finding[0]["summary"] = 'Synthetic escaped text: "]}, \\" Ω'
    value = {"findings": finding, **raw}
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert read_analysis(path) == Analysis.model_validate_json(path.read_bytes())


@pytest.mark.parametrize(
    "mutation",
    ["duplicate_ids", "incomplete_source", "unknown_field", "missing_findings", "unknown_schema"],
)
def test_incremental_reader_keeps_complete_analysis_validation(
    scenario: Scenario, tmp_path: Path, mutation: str
) -> None:
    raw = scenario.analyze().model_dump(mode="json")
    if mutation == "duplicate_ids":
        raw["findings"].append(raw["findings"][0])
    elif mutation == "incomplete_source":
        raw["sources"][0]["state"] = "error"
    elif mutation == "unknown_field":
        raw["unrecognized"] = "data"
    elif mutation == "missing_findings":
        raw.pop("findings")
    else:
        raw["schema_version"] = "2.0"
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        read_analysis(path)
