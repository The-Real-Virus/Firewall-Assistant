"""Bounded loaded-page projections of invented validated analyses."""

from datetime import timedelta
from importlib.resources import files

from PySide6.QtCore import Qt

from wfdiag.contracts.models import Analysis
from wfdiag.gui.forms import CaseView
from wfdiag.gui.read_models import EvidenceModel, FindingsModel


def data(count: int) -> Analysis:
    analysis = Analysis.model_validate_json(
        files("wfdiag").joinpath("gui/resources/synthetic-analysis.json").read_bytes()
    )
    first = next(finding for finding in analysis.findings if finding.event is not None)
    findings = []
    for index in range(count):
        reference = f"events:{index}"
        event = first.event.model_copy(update={"source_ref": reference, "record_id": index})
        findings.append(
            first.model_copy(
                update={
                    "finding_id": f"F{index}",
                    "event": event,
                    "event_refs": (reference,),
                    "evidence_refs": (reference,),
                }
            )
        )
    return Analysis.model_validate_json(
        analysis.model_copy(update={"findings": tuple(findings)}).model_dump_json()
    )


def test_default_500_page_and_last_page_do_not_materialize_the_entire_case(qtbot) -> None:
    analysis = data(1501)
    view = CaseView()
    qtbot.addWidget(view)
    view.bind(analysis, None)
    assert view.proxy.rowCount() == 500 and "of 1501" in view.page_label.text()
    model = view.proxy.sourceModel()
    assert isinstance(model, FindingsModel) and len(model.rows) <= 500
    assert model.finding(499).finding_id == "F499"
    view.load_page(1)
    assert view.selected().finding_id == "F500" and view.evidence_proxy.rowCount() == 500
    view.reveal.setChecked(True)
    view.load_page(3)
    assert view.proxy.rowCount() == 1 and view.selected().finding_id == "F1500"
    assert not view.reveal.isChecked() and not view.next_page.isEnabled()
    assert view.previous_page.isEnabled() and "loaded page only" in view.page_label.text()


def test_search_is_debounced_and_explicitly_not_exhaustive(qtbot) -> None:
    view = CaseView()
    qtbot.addWidget(view)
    view.bind(data(502), None)
    view.search.setText("No such category exists")
    assert view.proxy.rowCount() == 500
    qtbot.waitUntil(lambda: view.proxy.rowCount() == 0)
    assert (
        "loaded" in view.search.placeholderText() and "page only" in view.search.placeholderText()
    )
    view.search.clear()
    qtbot.waitUntil(lambda: view.proxy.rowCount() == 500)
    view.load_page(1)
    assert view.proxy.rowCount() == 2 and "of 502" in view.page_label.text()


def test_typed_port_address_and_time_sorting_only_after_deliberate_reveal(qtbot) -> None:
    analysis = data(3)
    ports = (10000, 9, 80)
    endings = (9, 10, 2)
    findings = tuple(
        finding.model_copy(
            update={
                "event": finding.event.model_copy(
                    update={
                        "source_port": ports[index],
                        "source_address": f"203.0.113.{endings[index]}",
                        "timestamp_utc": finding.event.timestamp_utc
                        + timedelta(microseconds=endings[index]),
                    }
                )
            }
        )
        for index, finding in enumerate(analysis.findings)
    )
    analysis = Analysis.model_validate_json(
        analysis.model_copy(update={"findings": findings}).model_dump_json()
    )
    view = CaseView()
    qtbot.addWidget(view)
    view.bind(analysis, None)
    source = view.evidence_proxy.sourceModel()
    assert isinstance(source, EvidenceModel)
    view.evidence_proxy.sort(4, Qt.SortOrder.AscendingOrder)
    assert view.evidence_proxy.mapToSource(view.evidence_proxy.index(0, 4)).row() == 0
    assert source.data(source.index(0, 4)) == "Hidden until Reveal"
    view.reveal.setChecked(True)

    def values(column, field):
        view.evidence_proxy.sort(column, Qt.SortOrder.AscendingOrder)
        return [
            getattr(
                source.events[
                    view.evidence_proxy.mapToSource(view.evidence_proxy.index(row, column)).row()
                ],
                field,
            )
            for row in range(3)
        ]

    assert values(4, "source_port") == [9, 80, 10000]
    assert values(3, "source_address") == ["203.0.113.2", "203.0.113.9", "203.0.113.10"]
    assert values(1, "timestamp_utc") == sorted(event.timestamp_utc for event in source.events)


def test_hidden_fields_are_not_searched_and_observation_selection_tracks_its_finding(qtbot) -> None:
    view = CaseView()
    qtbot.addWidget(view)
    view.bind(data(3), None)
    source = view.evidence_proxy.sourceModel()
    address = source.events[0].source_address
    assert address
    view.evidence_search.setText(address)
    qtbot.waitUntil(lambda: view.evidence_proxy.rowCount() == 0)
    view.reveal.setChecked(True)
    assert view.evidence_proxy.rowCount() == 3
    view.evidence_search.clear()
    qtbot.waitUntil(lambda: view.evidence_proxy.rowCount() == 3)
    view.evidence_table.selectRow(2)
    assert view.selected().finding_id == "F2"
    assert (
        not view.reveal.isChecked()
        and "Sensitive local details are hidden" in view.evidence.toPlainText()
    )


def test_evidence_column_sizing_does_not_visit_the_whole_loaded_page(qtbot, monkeypatch) -> None:
    seen = set()
    original = EvidenceModel.data

    def counted(self, index, role=Qt.ItemDataRole.DisplayRole):
        if index.isValid() and role == Qt.ItemDataRole.DisplayRole:
            seen.add(index.row())
        return original(self, index, role)

    monkeypatch.setattr(EvidenceModel, "data", counted)
    view = CaseView()
    qtbot.addWidget(view)
    view.resize(800, 600)
    view.bind(data(1501), None)
    view.tabs.setCurrentIndex(1)
    view.show()
    qtbot.waitUntil(lambda: len(seen) > 0)
    image = view.grab()
    assert not image.isNull()
    assert 0 < len(seen) <= 64  # Layout should inspect a bounded sample, not all500 rows.
    assert view.evidence_proxy.rowCount() == 500


def test_hidden_fields_are_not_formatted_and_repeated_reveal_state_is_quiet(qtbot) -> None:
    view = CaseView()
    qtbot.addWidget(view)
    view.bind(data(501), None)
    source = view.evidence_proxy.sourceModel()
    assert isinstance(source, EvidenceModel)
    changes = []
    source.dataChanged.connect(lambda *args: changes.append(True))
    for row in range(500):
        assert source.data(source.index(row, 3)) == "Hidden until Reveal"
    assert source.rows == {}
    source.reveal(False)
    assert not changes
    source.reveal(True)
    assert source.data(source.index(499, 3)) == source.events[499].source_address
    assert len(source.rows) == 1 and len(changes) == 1
    source.reveal(True)
    assert len(changes) == 1
    source.reveal(False)
    assert source.rows == {} and len(changes) == 2
    assert source.data(source.index(499, 3)) == "Hidden until Reveal"
