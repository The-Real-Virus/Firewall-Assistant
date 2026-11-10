"""Synthetic rule pages; no native policy/GUI acceptance is inferred."""

import json
from pathlib import Path

from wfdiag.contracts.models import Analysis, Rule
from wfdiag.gui.forms import CaseView
from wfdiag.gui.read_models import PolicyModel


def invented(count=502):
    analysis = Analysis.model_validate_json(
        (Path(__file__).parents[2] / "examples/expected-analysis.json").read_bytes()
    )
    conditions = {
        name: None
        for name in (
            "programs",
            "protocols",
            "local_ports",
            "remote_ports",
            "local_addresses",
            "remote_addresses",
            "services",
            "interfaces",
            "interface_types",
            "security",
        )
    }
    rules = tuple(
        Rule.model_validate_json(
            json.dumps(
                {
                    "rule_id": f"CANARY-RULE-{n}",
                    "display_name": '<a href="https://CANARY.invalid">Private rule</a>',
                    "enabled": True,
                    "action": "Block",
                    "direction": "inbound",
                    "profiles": ["Private"],
                    "policy_source": "CANARY private policy source",
                    "policy_source_type": "local",
                    "snapshot_utc": "2026-11-04T00:00:00Z",
                    "conditions": conditions,
                    "source_ref": f"rules:{n}",
                }
            )
        )
        for n in range(count)
    )
    finding = analysis.findings[0].model_copy(
        update={"candidate_rules": ("CANARY-RULE-0", "CANARY-RULE-501")}
    )
    return Analysis.model_validate_json(
        analysis.model_copy(
            update={"policy_rules": rules, "findings": (finding,)}
        ).model_dump_json()
    )


def test_policy_pages_candidates_and_sensitive_search_are_bounded(qtbot):
    view = CaseView()
    qtbot.addWidget(view)
    view.bind(invented(), None, synthetic=True)
    assert view.policy_proxy.rowCount() == 500
    source = view.policy_proxy.sourceModel()
    assert isinstance(source, PolicyModel) and len(source.rules) == 500
    assert "CANARY" not in str(source.data(source.index(0, 0)))
    assert "CANARY" not in view.policy_detail.toPlainText()
    view.policy_scope.setCurrentIndex(1)
    assert view.policy_proxy.rowCount() == 1  # Other candidate is on the next page.
    view.policy_search.setText("CANARY-RULE-0")
    qtbot.waitUntil(lambda: view.policy_proxy.rowCount() == 0)
    view.reveal.setChecked(True)
    assert view.policy_proxy.rowCount() == 1
    view.policy_table.selectRow(0)
    assert "https://CANARY.invalid" in view.policy_detail.toPlainText()
    assert "source_ref" in view.policy_detail.toPlainText()
    view.policy_search.clear()
    qtbot.waitUntil(lambda: view.policy_proxy.rowCount() == 1)
    view.load_policy_page(1)
    assert not view.reveal.isChecked() and view.policy_proxy.rowCount() == 1
    assert "of 502" in view.policy_page_label.text() and not view.next_policy.isEnabled()
    assert "CANARY" not in view.policy_detail.toPlainText()


def test_missing_policy_is_distinct_from_an_empty_snapshot_and_sources_remain_visible(qtbot):
    view = CaseView()
    qtbot.addWidget(view)
    analysis = invented(0)
    view.bind(analysis.model_copy(update={"policy_rules": None}), None)
    assert "unavailable" in view.policy_page_label.text()
    assert "no rules" in view.policy_page_label.text()
    assert "Source status" in view.source_detail.toPlainText()
    view.bind(analysis, None)
    assert "Rules 0–0 of 0" in view.policy_page_label.text()
    assert "unavailable" not in view.policy_page_label.text()
    view.reveal.setChecked(True)
    assert '"source"' in view.source_detail.toPlainText()
    view.reveal.setChecked(False)
    assert '"source"' not in view.source_detail.toPlainText()


def test_minimum_evidence_page_reaches_policy_and_provenance_controls(qtbot):
    view = CaseView()
    qtbot.addWidget(view)
    view.resize(800, 600)
    view.bind(invented(), None, synthetic=True)
    view.tabs.setCurrentIndex(1)
    view.show()
    qtbot.waitUntil(lambda: view.evidence_scroll.verticalScrollBar().maximum() > 0)
    view.evidence_scroll.ensureWidgetVisible(view.source_detail)
    assert view.evidence_scroll.verticalScrollBar().value() > 0
    assert view.policy_table.accessibleName() and view.source_detail.accessibleName()
