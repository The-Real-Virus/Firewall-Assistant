"""Held-file indexed view parity and off-page rejection, using invented records only."""

import hashlib
import json
import os
import sys
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest

from wfdiag.contracts.models import Analysis
from wfdiag.errors import DiagnosticError
from wfdiag.storage import analysis_index
from wfdiag.storage.analysis_index import AnalysisIndex, open_analysis_index, read_gui_analysis
from wfdiag.storage.atomic_write import write_new_bytes
from wfdiag.storage.records import MAX_ANALYSIS_BYTES, RecordByteBudgetExceeded, read_analysis


def raw_case(count: int = 1001) -> dict:
    raw = json.loads(files("wfdiag").joinpath("gui/resources/synthetic-analysis.json").read_bytes())
    finding = next(item for item in raw["findings"] if item.get("event") is not None)
    raw["findings"] = [
        {**finding, "finding_id": f"F{index}", "summary": f'Invented Ω 漢字 "]}}, \\" {index}'}
        for index in range(count)
    ]
    return raw


def save(path: Path, raw: dict, *, bom: bool = False) -> None:
    # Findings first exercises byte offsets independently of header order and UTF8 width.
    value = {"findings": raw["findings"], **{k: v for k, v in raw.items() if k != "findings"}}
    body = json.dumps(value, ensure_ascii=False).encode("utf-8")
    path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + body)


@pytest.mark.parametrize("bom", [False, True])
def test_index_all_pages_match_full_reader_and_hold_only_a_page(tmp_path: Path, bom: bool) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(), bom=bom)
    expected = read_analysis(path)
    index = open_analysis_index(path)
    try:
        assert index.count == 1001
        assert index.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
        assert index.metadata.findings == ()
        assert len(index.first_page.findings) == 500
        assert tuple(f for page in index.iter_pages() for f in page.findings) == expected.findings
        assert index.read_page(2).findings[0].finding_id == "F1000"
        assert index.read_page(0).findings[0].summary == expected.findings[0].summary
        assert (
            Analysis.model_validate_json(path.read_bytes().removeprefix(b"\xef\xbb\xbf"))
            == expected
        )
    finally:
        index.close()
    index.close()
    with pytest.raises(ValueError, match="closed"):
        index.read_page(0)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "offpage_type",
        "offpage_extra",
        "root_extra",
        "missing",
        "schema",
        "source",
        "utc",
        "incomplete_eligible",
        "no_intent_eligible",
        "unconfirmed_eligible",
    ],
)
def test_index_rejects_invalid_offpage_and_global_semantics(tmp_path: Path, mutation: str) -> None:
    raw = raw_case()
    if mutation == "duplicate":
        raw["findings"][-1]["finding_id"] = raw["findings"][0]["finding_id"]
    elif mutation == "offpage_type":
        raw["findings"][-1]["proposal_eligible"] = "false"
    elif mutation == "offpage_extra":
        raw["findings"][-1]["injected"] = True
    elif mutation == "root_extra":
        raw["injected"] = True
    elif mutation == "missing":
        raw.pop("intent")
    elif mutation == "schema":
        raw["schema_version"] = "999"
    elif mutation == "source":
        raw["sources"][0]["state"] = "error"
    elif mutation == "utc":
        raw["analyzed_at_utc"] = "2026-01-01T00:00:00"
    else:
        finding = raw["findings"][-1]
        finding.update(
            category="DEFAULT_BLOCK",
            evidence_grade="supported",
            relevance="relevant",
            proposal_eligible=True,
            refusal_codes=[],
        )
        raw["intent"]["application_identity_confirmed"] = True
        # Prove this witness is valid first; each rejection below must be caused
        # by the global context mutation, rather than an invalid Finding fixture.
        Analysis.model_validate_json(json.dumps(raw))
        if mutation == "incomplete_eligible":
            raw["completeness"] = "incomplete"
        elif mutation == "no_intent_eligible":
            raw["intent"] = None
        else:
            raw["intent"]["application_identity_confirmed"] = False
    path = tmp_path / "analysis.json"
    save(path, raw)
    with pytest.raises(ValueError):
        read_analysis(path)
    with pytest.raises(ValueError):
        open_analysis_index(path)
    # Every refused open released its handles (especially Windows deny-write/delete).
    path.unlink()


def test_index_preserves_valid_offpage_eligibility(tmp_path: Path) -> None:
    raw = raw_case(501)
    raw["intent"]["application_identity_confirmed"] = True
    raw["findings"][-1].update(
        category="DEFAULT_BLOCK",
        evidence_grade="supported",
        relevance="relevant",
        proposal_eligible=True,
        refusal_codes=[],
    )
    path = tmp_path / "analysis.json"
    save(path, raw)
    expected = read_analysis(path)
    index = open_analysis_index(path)
    try:
        assert index.read_page(1).findings == expected.findings[500:]
        assert index.read_page(1).findings[0].proposal_eligible
    finally:
        index.close()


def test_index_page_bounds_and_new_incomplete_marker(tmp_path: Path) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(0))
    index = open_analysis_index(path)
    try:
        assert index.count == 0 and index.read_page(0).findings == ()
        for page in (-1, 1, True):
            with pytest.raises(ValueError, match="page"):
                index.read_page(page)
        (tmp_path / ".incomplete").write_text("interrupted", encoding="utf-8")
        with pytest.raises(DiagnosticError):
            index.read_page(0)
        with pytest.raises(DiagnosticError):
            open_analysis_index(path)
    finally:
        index.close()


def test_index_refuses_changed_identity_and_cleans_up(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(1))
    index = open_analysis_index(path)
    real = analysis_index._identity
    monkeypatch.setattr(analysis_index, "_identity", lambda stream: (*real(stream)[:4], -1))
    try:
        with pytest.raises(ValueError, match="changed"):
            index.read_page(0)
    finally:
        index.close()
    path.unlink()


def test_gui_threshold_does_not_change_engine_reader(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(1))
    assert isinstance(read_gui_analysis(path), Analysis)
    monkeypatch.setattr(analysis_index, "INDEX_THRESHOLD_BYTES", 1)
    result = read_gui_analysis(path)
    assert isinstance(result, AnalysisIndex)
    try:
        assert read_analysis(path) == result.first_page
    finally:
        result.close()


def test_small_reader_budget_is_enforced_on_held_file_before_decode(tmp_path: Path) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(1))
    size = path.stat().st_size
    with pytest.raises(RecordByteBudgetExceeded):
        read_analysis(path, byte_limit=size - 1)
    assert read_analysis(path, byte_limit=size) == read_analysis(path)
    for invalid in (0, -1, MAX_ANALYSIS_BYTES + 1, True):
        with pytest.raises(ValueError, match="budget"):
            read_analysis(path, byte_limit=invalid)


def test_stale_path_size_cannot_route_large_held_file_to_full_models(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(501))
    real_stat = Path.stat
    monkeypatch.setattr(analysis_index, "INDEX_THRESHOLD_BYTES", 1)

    def stale_stat(candidate, *args, **kwargs):
        info = real_stat(candidate, *args, **kwargs)
        if candidate == path:
            # Emulate stale pathname metadata after replacement; native fstat on
            # the actually opened file remains untouched and sees the real size.
            return SimpleNamespace(
                **{
                    name: 0 if name == "st_size" else getattr(info, name)
                    for name in dir(info)
                    if name.startswith("st_")
                }
            )
        return info

    monkeypatch.setattr(Path, "stat", stale_stat)
    result = read_gui_analysis(path)
    assert isinstance(result, AnalysisIndex)
    try:
        assert result.count == 501 and result.read_page(1).findings[0].finding_id == "F500"
    finally:
        result.close()


def test_index_byte_budget_duplicate_property_and_hardlink(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(1))
    monkeypatch.setattr(analysis_index, "MAX_ANALYSIS_BYTES", path.stat().st_size - 1)
    with pytest.raises(ValueError, match="budget"):
        open_analysis_index(path)
    monkeypatch.undo()
    path.write_bytes(b'{"findings":[],"findings":[]}')
    with pytest.raises(ValueError):
        open_analysis_index(path)
    alias = tmp_path / "alias.json"
    os.link(path, alias)
    with pytest.raises((ValueError, OSError)):
        open_analysis_index(path)


def test_index_allows_atomic_new_sibling_but_preserves_held_input(tmp_path: Path) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(501))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    index = open_analysis_index(path)
    try:
        write_new_bytes(tmp_path / "new-share.json", b'{"synthetic":"new output"}')
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before
        assert index.read_page(1).findings[0].finding_id == "F500"
        if sys.platform == "win32":
            with pytest.raises(PermissionError):
                path.write_bytes(b"must not overwrite the held input")
            assert index.read_page(1).findings[0].finding_id == "F500"
        else:
            path.write_bytes(b"changed synthetic input")
            with pytest.raises(ValueError, match="changed"):
                index.read_page(1)
    finally:
        index.close()


def test_index_never_accepts_new_hardlink_on_a_held_input(tmp_path: Path) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(1))
    index = open_analysis_index(path)
    try:
        try:
            os.link(path, tmp_path / "extra-link.json")
        except OSError as error:
            assert sys.platform == "win32" and error.winerror in (5, 32)
            assert len(index.read_page(0).findings) == 1
        else:
            with pytest.raises(ValueError, match="changed|singly linked"):
                index.read_page(0)
    finally:
        index.close()


def test_normal_page_reads_one_bounded_span_without_losing_records(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "analysis.json"
    save(path, raw_case(501))
    index = open_analysis_index(path)
    reads = []
    original = index._stream.read

    def counted(size):
        reads.append(size)
        return original(size)

    monkeypatch.setattr(index._stream, "read", counted)
    try:
        page = index.read_page(0)
        assert len(page.findings) == 500 and page.findings[-1].finding_id == "F499"
        assert len(reads) == 1 and reads[0] <= analysis_index.MAX_PAGE_BATCH_BYTES
    finally:
        index.close()


def test_inter_record_whitespace_cannot_inflate_page_batch_buffer(
    tmp_path: Path, monkeypatch
) -> None:
    raw = raw_case(3)
    findings = raw.pop("findings")
    text = (
        '{"findings":['
        + json.dumps(findings[0])
        + ","
        + " " * (analysis_index.MAX_PAGE_BATCH_BYTES + 1)
        + ",".join(json.dumps(finding) for finding in findings[1:])
        + "],"
        + json.dumps(raw)[1:]
    )
    path = tmp_path / "analysis.json"
    path.write_text(text, encoding="utf-8")
    index = open_analysis_index(path)
    reads = []
    original = index._stream.read

    def counted(size):
        reads.append(size)
        return original(size)

    monkeypatch.setattr(index._stream, "read", counted)
    try:
        page = index.read_page(0)
        assert [finding.finding_id for finding in page.findings] == ["F0", "F1", "F2"]
        assert len(reads) == 3 and max(reads) < analysis_index.MAX_PAGE_BATCH_BYTES
    finally:
        index.close()
