"""Whole generated-report validation discards rows, never skips off-page defects."""

import json
from pathlib import Path

import pytest
from engine_data import Scenario, changed

from wfdiag.reporting.limits import MAX_HTML_REPORT_BYTES, MAX_JSON_REPORT_BYTES, report_byte_limit
from wfdiag.reporting.share import make_share_report
from wfdiag.reporting.validation import (
    MAX_FINDING_CHARACTERS,
    MAX_METADATA_CHARACTERS,
    validate_share_report,
)


def data(scenario: Scenario, count: int = 501) -> dict:
    analysis = scenario.analyze()
    analysis = changed(
        analysis,
        findings=[
            {**analysis.findings[0].model_dump(mode="json"), "finding_id": f"F{i}"}
            for i in range(count)
        ],
    )
    return make_share_report(analysis).model_dump(mode="json")


def save(path: Path, raw: dict, bom=False) -> None:
    value = {
        "findings": raw["findings"],
        **{key: value for key, value in raw.items() if key != "findings"},
    }
    body = json.dumps(value, ensure_ascii=False).encode("utf-8")
    path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + body)


@pytest.mark.parametrize("bom", [False, True])
def test_complete_summary_accepts_reordered_utf8_but_returns_no_partial_model(
    scenario, tmp_path, bom
):
    raw = data(scenario)
    raw["excluded"] = ["Invented Ω 漢字 explanation"]
    path = tmp_path / "share.json"
    save(path, raw, bom)
    assert validate_share_report(path) == 501
    path.unlink()  # Every held handle closed after complete validation.


@pytest.mark.parametrize(
    "mutation",
    [
        "last_type",
        "last_extra",
        "last_alias",
        "schema",
        "review",
        "extra",
        "oversized_item",
        "oversized_metadata",
    ],
)
def test_last_record_and_header_errors_refuse_entire_report(scenario, tmp_path, mutation):
    raw = data(scenario)
    if mutation == "last_type":
        raw["findings"][-1]["proposal_eligible"] = "false"
    elif mutation == "last_extra":
        raw["findings"][-1]["unknown"] = True
    elif mutation == "last_alias":
        raw["findings"][-1]["finding_alias"] = "unapproved-alias"
    elif mutation == "schema":
        raw["schema_version"] = "2.0"
    elif mutation == "review":
        raw["review_required"] = False
    elif mutation == "extra":
        raw["injected"] = "data"
    elif mutation == "oversized_item":
        raw["findings"][-1]["evidence_aliases"] = ["x" * (MAX_FINDING_CHARACTERS + 1)]
    else:
        raw["excluded"] = ["x" * (MAX_METADATA_CHARACTERS + 1)]
    path = tmp_path / "share.json"
    save(path, raw)
    with pytest.raises(ValueError):
        validate_share_report(path)
    path.unlink()


def test_row_count_comes_from_declared_report_schema(scenario, tmp_path, monkeypatch):
    from wfdiag.reporting.share import ShareReport

    raw = data(scenario, 2)
    path = tmp_path / "share.json"
    save(path, raw)
    original = ShareReport.model_json_schema

    def smaller(*args, **kwargs):
        schema = original(*args, **kwargs)
        schema["properties"]["findings"]["maxItems"] = 1
        return schema

    monkeypatch.setattr(ShareReport, "model_json_schema", smaller)
    with pytest.raises(ValueError, match="count"):
        validate_share_report(path)


def test_input_json_and_html_expansion_budgets_are_separate() -> None:
    assert report_byte_limit("json") == MAX_JSON_REPORT_BYTES == 128 * 1024 * 1024
    assert report_byte_limit("html") == MAX_HTML_REPORT_BYTES == 256 * 1024 * 1024
    with pytest.raises(ValueError):
        report_byte_limit("untrusted-format")
