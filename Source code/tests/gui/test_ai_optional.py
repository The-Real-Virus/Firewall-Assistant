"""End-user connection/chat/application-action journeys with fake provider HTTP streams."""

import json
import socket

import httpx
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLineEdit

from wfdiag.ai.assistant import AppAction
from wfdiag.ai.contracts import AiErrorCode, Provider
from wfdiag.ai.credentials import SessionKeys
from wfdiag.ai.models import MODELS
from wfdiag.ai.policy import AiFailure
from wfdiag.gui.main_window import MainWindow


class Stream(httpx.AsyncByteStream):
    def __init__(self, value):
        self.value = json.dumps(value).encode()

    async def __aiter__(self):
        yield self.value


def reply(model, message, actions=()):
    value = json.dumps({"message": message, "actions": list(actions)})
    if model.provider == Provider.GOOGLE:
        return {
            "candidates": [
                {"finishReason": "STOP", "content": {"role": "model", "parts": [{"text": value}]}}
            ]
        }
    if model.provider == Provider.ANTHROPIC:
        return {
            "type": "message",
            "role": "assistant",
            "model": model.model,
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": value}],
        }
    return {
        "status": "completed",
        "model": model.model,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": value}],
            }
        ],
    }


@pytest.fixture
def window(qtbot, monkeypatch):
    original_connect = socket.socket.connect

    def forbidden(*args, **kwargs):
        raise AssertionError("No live provider network in GUI tests")

    def guarded(sock, address):
        if isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1"):
            return original_connect(sock, address)
        return forbidden()

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", guarded)
    widget = MainWindow()
    qtbot.addWidget(widget)
    widget.show()
    yield widget
    widget.ai_destination.shutdown()
    qtbot.waitUntil(lambda: widget.ai_destination.view is None, timeout=6000)
    widget.close()


def setup(window, qtbot, model=MODELS[2], messages=None, status=200):
    window.navigate(5)
    window.ai_destination.toggle_enabled()
    view = window.ai_destination.view
    assert view is not None
    view.provider.setCurrentIndex(view.provider.findData(model.provider.value))
    view.model.setCurrentIndex(view.model.findData(model.model))
    calls = []
    responses = list(messages or [("Connected", [])])

    def handler(request):
        calls.append(request.content)
        if status != 200:
            return httpx.Response(
                status,
                headers={"content-type": "application/json"},
                stream=Stream({"error": {"status": "UNAVAILABLE"}}),
            )
        message, actions = responses.pop(0) if responses else ("A helpful follow-up answer.", [])
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=Stream(reply(model, message, actions)),
        )

    view._test_transport = httpx.MockTransport(handler)
    view.key.setText("invented-session-key")
    return view, calls


def connect(view, qtbot):
    view.connect_button.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=6000)
    assert view.connected


@pytest.mark.parametrize("model", MODELS)
def test_simple_connection_then_typed_question_and_followup(window, qtbot, model):
    view, calls = setup(window, qtbot, model)
    assert not calls and not view.connected
    assert view.key.echoMode() == QLineEdit.EchoMode.Password
    connect(view, qtbot)
    assert view.connection.isHidden() and view.chat_panel.isVisible()
    view.question.setPlainText("Hi, what can you do?")
    qtbot.keyClick(view.question, Qt.Key.Key_Return)
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=6000)
    original = view.conversation.toPlainText()
    assert "helpful follow-up" in original
    view.question.setPlainText("What should I check next?")
    assert view.conversation.toPlainText() == original
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=6000)
    assert len(view.chat.history) == 4 and len(calls) == 3
    assert b"Hi, what can you do?" in calls[-1]
    assert "invented-session-key" not in view.preview.toPlainText()


def test_chat_executes_real_application_example_and_reads_engine_facts(window, qtbot):
    action = AppAction(name="open_example").model_dump(mode="json")
    view, calls = setup(
        window,
        qtbot,
        messages=[
            ("Connected", []),
            ("Opening an example.", [action]),
            ("The engine found a supported default block.", []),
        ],
    )
    connect(view, qtbot)
    view.question.setPlainText("Open the example and explain it")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=10000)
    assert window.example_open and window.case_view.analysis is not None
    assert window.pages.currentIndex() == 5  # Final answer stays visible in chat.
    assert "Open example · completed" in view.conversation.toPlainText()
    assert "supported default block" in view.conversation.toPlainText()
    assert b"DEFAULT_BLOCK" in calls[-1]


@pytest.mark.parametrize("chosen", [True, False])
def test_assistant_case_chooser_does_not_claim_a_missing_or_cancelled_case_was_opened(
    window, qtbot, tmp_path, monkeypatch, chosen
):
    from PySide6.QtWidgets import QFileDialog

    monkeypatch.setattr(
        QFileDialog, "getExistingDirectory", lambda *args: str(tmp_path) if chosen else ""
    )
    action = AppAction(name="choose_case").model_dump(mode="json")
    view, calls = setup(
        window,
        qtbot,
        messages=[
            ("Connected", []),
            ("Choose your case.", [action]),
            ("No case was opened.", []),
        ],
    )
    connect(view, qtbot)
    view.question.setPlainText("Open my case")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=10000)
    assert window.case_view.analysis is None and len(calls) == 3
    assert b'"status":"completed"' not in calls[-1]
    assert (b"CASE_FILES_MISSING" if chosen else b"NO_CASE_CHOSEN") in calls[-1]


@pytest.mark.parametrize(
    "status,label",
    [
        (401, "did not accept"),
        (403, "refused"),
        (404, "cannot use"),
        (429, "rate limit"),
        (500, "could not finish"),
    ],
)
def test_connection_errors_are_short_actionable_and_do_not_break_core(window, qtbot, status, label):
    view, calls = setup(window, qtbot, status=status)
    view.connect_button.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=6000)
    assert not view.connected and label in view.status.text()
    assert len(calls) == 1
    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    assert window.case_view.analysis is not None


def test_entered_key_does_not_connect_or_send_until_explicit_click(window, qtbot):
    view, calls = setup(window, qtbot)
    view.question.setPlainText("Hello")
    assert not view.send.isEnabled() and not calls
    assert not view.remember.isChecked()
    assert view.chat.connection is None


def test_missing_key_has_no_provider_request(window, qtbot):
    view, calls = setup(window, qtbot)
    view.key.clear()
    view.connect_button.click()
    qtbot.waitUntil(lambda: not view.controller.busy)
    assert not calls and not view.connected
    assert "API key" in view.status.text()


def test_remember_failure_keeps_session_choice_explicit(window, qtbot):
    view, calls = setup(window, qtbot)

    class Store:
        def write(self, provider, key):
            raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)

    view.keys = SessionKeys(lambda: Store())
    view.remember.setChecked(True)
    view.connect_button.click()
    qtbot.waitUntil(lambda: not view.controller.busy)
    assert not calls and not view.connected and "Turn off Remember" in view.status.text()
    view.remember.setChecked(False)
    connect(view, qtbot)
    assert len(calls) == 1


def test_arbitrary_action_is_rejected_before_any_app_dispatch(window, qtbot, monkeypatch):
    view, _calls = setup(
        window,
        qtbot,
        messages=[("Connected", []), ("Unsafe action", [{"name": "shell", "command": "CANARY"}])],
    )
    connect(view, qtbot)
    dispatched = []
    monkeypatch.setattr(view.tools, "_dispatch", lambda action: dispatched.append(action))
    view.question.setPlainText("Help")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy)
    assert not dispatched and "unsupported reply" in view.status.text()


def test_disable_clears_connection_chat_and_keys(window, qtbot):
    view, _calls = setup(window, qtbot)
    connect(view, qtbot)
    view.question.setPlainText("Hello")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy)
    session = view.chat
    window.ai_destination.disable()
    qtbot.waitUntil(lambda: window.ai_destination.view is None)
    assert session.connection is None and not session.history
    assert view.keys.get(Provider.GOOGLE) is None
    assert window.ai_status_label.text() == "AI is off"


def test_new_chat_preserves_connection_and_normal_drafting(window, qtbot):
    view, _calls = setup(window, qtbot)
    connect(view, qtbot)
    view.question.setPlainText("Hello")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy)
    view.clear.click()
    assert not view.chat.history and view.connected
    view.question.setPlainText("Another question")
    assert view.send.isEnabled()


def test_changing_provider_requires_new_verified_connection(window, qtbot):
    view, calls = setup(window, qtbot)
    connect(view, qtbot)
    view.change_connection.click()
    view.provider.setCurrentIndex(view.provider.findData(Provider.OPENAI.value))
    assert not view.connected and view.chat.connection is None and not view.key.text()
    assert len(calls) == 1


def test_plain_rendering_never_turns_model_links_or_html_into_browser_actions(window, qtbot):
    view, _calls = setup(window, qtbot)
    view.append("Assistant", "<script>CANARY</script> [click](https://invalid.example)")
    assert not view.conversation.openExternalLinks() and not view.conversation.openLinks()
    assert "<script>CANARY</script>" in view.conversation.toPlainText()


def test_indexed_case_identifiers_are_redacted_even_when_off_the_displayed_page(
    window, qtbot, tmp_path
):
    from wfdiag.contracts.models import Analysis
    from wfdiag.storage.analysis_index import open_analysis_index

    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    original = window.case_view.analysis
    finding = original.findings[0].model_dump(mode="json")
    raw = original.model_dump(mode="json")
    raw["findings"] = [{**finding, "finding_id": f"F{i}"} for i in range(501)]
    raw["findings"][-1]["event"]["unknown_fields"] = {"user-name": "OffpageOwnerIdentity"}
    path = tmp_path / "analysis.json"
    path.write_text(
        Analysis.model_validate_json(json.dumps(raw)).model_dump_json(), encoding="utf-8"
    )
    index = open_analysis_index(path)
    window.controller.bind(index, path)
    view, calls = setup(window, qtbot)
    connect(view, qtbot)
    view.question.setPlainText("Why does OffpageOwnerIdentity appear?")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=10000)
    assert len(calls) == 2 and b"OffpageOwnerIdentity" not in calls[-1]
    assert view.chat.history and "OffpageOwnerIdentity" not in str(view.chat.history)


def test_chat_preserves_engine_uncertainty_without_disclosing_private_text(window, qtbot):
    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    view, calls = setup(window, qtbot)
    connect(view, qtbot)
    finding = window.case_view.analysis.findings[0]
    snapshot = view.tools.snapshot()
    sent_finding = snapshot["findings"][0]
    assert sent_finding["limitations_count"] == len(finding.limitations) > 0
    assert sent_finding["alternative_explanations_count"] == len(finding.alternative_explanations)
    assert sent_finding["next_steps"] == [step.value for step in finding.next_steps]
    view.question.setPlainText("What is certain and uncertain?")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=10000)
    assert len(calls) == 2
    wire = calls[-1].decode()
    assert "limitations_count" in wire and "current_policy_is_not_event_time_proof" in wire
    assert "not certainty or repair" in wire
    assert all(value not in wire for value in finding.limitations)
    assert all(value not in wire for value in finding.alternative_explanations)


def test_chat_keeps_the_latest_long_reply_visible_after_layout(window, qtbot):
    view, _calls = setup(window, qtbot)
    connect(view, qtbot)
    for index in range(20):
        view.append("Assistant", f"Message {index}\n" + "A readable explanation. " * 80)
    bar = view.conversation.verticalScrollBar()
    qtbot.waitUntil(lambda: bar.maximum() > 0 and bar.value() == bar.maximum())


def test_disable_cancels_pending_http_and_keeps_gui_responsive(window, qtbot):
    import asyncio
    import threading

    from PySide6.QtCore import QTimer

    view, _calls = setup(window, qtbot)
    connect(view, qtbot)
    started, closed = threading.Event(), threading.Event()

    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self):
            started.set()
            await asyncio.sleep(30)
            yield b"{}"

        async def aclose(self):
            closed.set()

    view._test_transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, headers={"content-type": "application/json"}, stream=Slow()
        )
    )
    view.question.setPlainText("Explain firewall profiles")
    view.send.click()
    qtbot.waitUntil(started.is_set)
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    qtbot.waitUntil(lambda: len(ticks) >= 3)
    window.ai_destination.disable()
    qtbot.waitUntil(lambda: window.ai_destination.view is None, timeout=6000)
    timer.stop()
    assert closed.is_set() and view.controller.worker_thread is None
    assert not view.chat.history and view.keys.get(Provider.GOOGLE) is None


@pytest.mark.parametrize("training_example", [False, True])
def test_assistant_export_uses_real_qprocess_engine_and_validated_report(
    window, qtbot, tmp_path, monkeypatch, training_example
):
    import sys
    from pathlib import Path

    from wfdiag.contracts.models import Analysis
    from wfdiag.gui import controller, jobs

    source = Path(__file__).parents[2] / "examples/expected-analysis.json"
    if training_example:
        window.open_example()
        qtbot.waitUntil(lambda: not window.controller.busy)
        assert window.case_view.synthetic and window.case_view.path is None
        assert window.case_view.share_button.isEnabled()
    else:
        window.controller.bind(Analysis.model_validate_json(source.read_bytes()), source)
    window.controller.root = tmp_path
    monkeypatch.setattr(controller, "prepare_work_root", lambda path: path)
    monkeypatch.setattr(controller, "create_private_directory", lambda path: path.mkdir())
    monkeypatch.setattr(jobs, "create_private_directory", lambda path: path.mkdir())
    bootstrap = "from wfdiag.services import desktop_worker as w;w.verify_private_directory=lambda p:None;from wfdiag.cli import main;raise SystemExit(main())"
    monkeypatch.setattr(jobs, "engine_command", lambda: (sys.executable, ["-I", "-c", bootstrap]))
    action = AppAction(name="export_report", report_mode="share").model_dump(mode="json")
    view, calls = setup(
        window,
        qtbot,
        messages=[
            ("Connected", []),
            ("Preparing your report.", [action]),
            ("The redacted report is ready.", []),
        ],
    )
    connect(view, qtbot)
    view.question.setPlainText("Export a share report")
    view.send.click()
    qtbot.waitUntil(lambda: not view.controller.busy, timeout=15000)
    assert len(calls) == 3
    assert view.tools.artifacts and view.tools.artifacts[-1].is_file()
    assert "default-src 'none'" in view.tools.artifacts[-1].read_text(encoding="utf-8")
    assert "Export report · completed" in view.conversation.toPlainText()
    assert b"App action" not in calls[-1]
    if training_example:
        assert window.case_view.synthetic and not window.case_view.proposal_button.isEnabled()
        assert window.case_view.path.is_file()
