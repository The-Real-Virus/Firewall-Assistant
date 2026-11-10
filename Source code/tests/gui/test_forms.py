"""GUI decisions use shared schemas and validated records; no native privacy claims."""

from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from pytestqt.qtbot import QtBot

from wfdiag.contracts.models import Analysis
from wfdiag.gui.forms import CaseView, IntentForm
from wfdiag.gui.main_window import MainWindow
from wfdiag.gui.read_models import FindingsModel

ROOT = Path(__file__).parents[2]


def fill(form: IntentForm) -> None:
    form.enabled.setChecked(True)
    form.application.setText(r"C:\Training\ExampleApp.exe")
    form.port.setText("443")
    form.profile.setCurrentText("Private")
    form.peer.setText("192.0.2.10/32")
    form.purpose.setText("Synthetic approved service")


def test_intent_direction_uses_stable_service_port(qtbot: QtBot) -> None:
    form = IntentForm()
    qtbot.addWidget(form)
    assert form.value() is None
    fill(form)
    outbound = form.value()
    assert outbound is not None
    assert outbound.remote_port == 443 and outbound.local_port is None
    assert not outbound.application_identity_confirmed
    form.direction.setCurrentIndex(1)
    inbound = form.value()
    assert inbound is not None and inbound.local_port == 443 and inbound.remote_port is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("port", "70000"),
        ("port", "４４３"),
        ("peer", "0.0.0.0/0"),
        ("application", r"\\server\share\app.exe"),
        ("purpose", ""),
    ],
)
def test_shared_schema_refuses_invalid_flow(qtbot: QtBot, field: str, value: str) -> None:
    form = IntentForm()
    qtbot.addWidget(form)
    fill(form)
    getattr(form, field).setText(value)
    with pytest.raises(ValueError):
        form.value()


def test_bundled_example_is_the_tested_engine_record() -> None:
    package = ROOT / "src/wfdiag/gui/resources/synthetic-analysis.json"
    assert package.read_bytes() == (ROOT / "examples/expected-analysis.json").read_bytes()
    assert Analysis.model_validate_json(package.read_bytes()).engine_version == "1.0.0rc1"


def test_alias_projection_and_explicit_reveal_are_plain_text(qtbot: QtBot) -> None:
    data = Analysis.model_validate_json((ROOT / "examples/expected-analysis.json").read_bytes())
    record = data.model_dump(mode="json")
    record["findings"][0]["observation"] = '<a href="https://CANARY.invalid">CANARY</a>'
    analysis = Analysis.model_validate_json(__import__("json").dumps(record))
    view = CaseView()
    qtbot.addWidget(view)
    view.bind(analysis, None, synthetic=True)
    assert "CANARY" not in view.evidence.toPlainText()
    assert "CANARY" not in view.detail.toPlainText()
    source = view.proxy.sourceModel()
    assert isinstance(source, FindingsModel)
    assert str(source.data(source.index(0, 2), Qt.ItemDataRole.DisplayRole)).startswith(
        "Application"
    )
    view.reveal.setChecked(True)
    assert '<a href=\\"https://CANARY.invalid' in view.evidence.toPlainText()
    assert view.share_button.isEnabled() and not view.proposal_button.isEnabled()


def test_changed_intent_keeps_old_findings_and_withholds_proposal(qtbot: QtBot) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    analysis = Analysis.model_validate_json((ROOT / "examples/expected-analysis.json").read_bytes())
    window.controller.bind(analysis, ROOT / "examples/expected-analysis.json")
    rows = window.table.model().rowCount()
    fill(window.intent_form)
    assert window.case_view.stale
    assert "Reanalyze" in window.case_view.status.text()
    assert window.table.model().rowCount() == rows
    assert not window.case_view.proposal_button.isEnabled()
    window.close()


def test_invalid_case_does_not_replace_current_case(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow()
    qtbot.addWidget(window)
    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    old = window.case_view.analysis
    window.controller.open_analysis(tmp_path / "missing.json")
    qtbot.waitUntil(lambda: not window.controller.busy)
    assert "Failed" in window.job_status.text()
    assert window.case_view.analysis is old
    assert window.controller.jobs is None
    window.close()
