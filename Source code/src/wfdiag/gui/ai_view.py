"""Simple connected chat with bounded access to the application's own services."""

import html
from itertools import chain
from typing import TYPE_CHECKING

from PySide6.QtCore import QElapsedTimer, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QKeyEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from wfdiag.ai.assistant import AssistantSession, ChatPrivacy
from wfdiag.ai.context import private_values
from wfdiag.ai.contracts import AiErrorCode, AiUsage, Provider
from wfdiag.ai.credentials import SessionKeys
from wfdiag.ai.models import CHAT_MODELS, selected_model
from wfdiag.ai.policy import AiFailure
from wfdiag.ai.service import AiSession
from wfdiag.gui.ai_controller import AiController
from wfdiag.gui.assistant_tools import ApplicationTools

if TYPE_CHECKING:
    from wfdiag.gui.main_window import MainWindow

ERRORS = {
    AiErrorCode.CONFIGURATION.value: "Check the selected provider, model and API key, then connect again.",
    AiErrorCode.AUTHENTICATION.value: "The provider did not accept this API key. Check or replace it in Connection settings.",
    AiErrorCode.CREDENTIAL_STORAGE.value: "Windows could not save this key. Turn off Remember and connect for this session instead.",
    AiErrorCode.MODEL_UNAVAILABLE.value: "This account cannot use the selected model. Check model access or choose another reviewed provider.",
    AiErrorCode.NETWORK.value: "Could not reach the provider. Check the internet connection; diagnostics still work offline.",
    AiErrorCode.TIMEOUT.value: "The provider took too long. You can retry deliberately; an earlier request may still be billed.",
    AiErrorCode.RATE_LIMIT.value: "The provider's rate limit was reached. Wait before sending again.",
    AiErrorCode.CREDIT.value: "The provider reports unavailable credit or quota. Check your provider account.",
    AiErrorCode.QUOTA.value: "The provider reports a quota limit. Check your provider account or try again when its quota resets.",
    AiErrorCode.POLICY.value: "The provider refused this request or the account lacks permission. Try a different question or check account access.",
    AiErrorCode.DISCLOSURE.value: "This message contains private data that could not be safely hidden. Remove secrets or identifying details and try again.",
    AiErrorCode.RESPONSE_INVALID.value: "The provider returned an incomplete or unsupported reply. Your case and findings are unchanged.",
    AiErrorCode.CANCELLED.value: "Stopped. Completed application actions remain visible below.",
}


def text(value: str) -> QLabel:
    label = QLabel(value)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


class Composer(QPlainTextEdit):
    submitted = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if (
            event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and not event.modifiers() & Qt.KeyboardModifier.ShiftModifier
        ):
            event.accept()
            self.submitted.emit()
        else:
            super().keyPressEvent(event)


class AiView(QWidget):
    progress_message = Signal(str)

    def __init__(self, window: "MainWindow", session: AiSession | None = None) -> None:
        super().__init__()
        self.host_window = window
        self.chat = session if isinstance(session, AssistantSession) else AssistantSession()
        self.controller = AiController(self, self.chat)
        self.keys = SessionKeys()
        self.tools = ApplicationTools(window, self)
        self.disabled = False
        self.mode_action = ""
        self.messages: list[tuple[str, str]] = []
        self._test_transport = None
        self.connected = False
        self.question: Composer
        self._last_artifact_count = 0
        self.phase_text = ""
        self.elapsed = QElapsedTimer()
        self.wait_timer = QTimer(self)
        self.wait_timer.setInterval(1000)
        self.wait_timer.timeout.connect(self.show_wait)
        self.controller.result.connect(self.completed)
        self.controller.activity.connect(self.activity)
        self.progress_message.connect(self.status_message)
        self.tools.activity.connect(self.tool_activity)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        self.status = text("Choose your provider and connect to start chatting.")
        self.status.setObjectName("badge")
        self.status.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        layout.addWidget(self.status)
        self.connection = QFrame()
        self.connection.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self.connection.setObjectName("card")
        form = QVBoxLayout(self.connection)
        form.setContentsMargins(16, 12, 16, 12)
        self.provider = QComboBox()
        self.provider.setAccessibleName("AI provider")
        for value, name in [
            (Provider.GOOGLE, "Google Gemini"),
            (Provider.OPENAI, "OpenAI"),
            (Provider.ANTHROPIC, "Anthropic Claude"),
        ]:
            self.provider.addItem(name, value.value)
        self.model = QComboBox()
        self.model.setAccessibleName("AI model")
        provider_row = QHBoxLayout()
        provider_row.addWidget(self.provider)
        provider_row.addWidget(self.model)
        form.addLayout(provider_row)
        self.key = QLineEdit()
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.key.setMaxLength(2560)
        self.key.setPlaceholderText("Paste this provider's API key here")
        self.key.setAccessibleName("Masked API key")
        form.addWidget(self.key)
        self.remember = QCheckBox("Remember on this Windows account")
        form.addWidget(self.remember)
        row = QHBoxLayout()
        self.connect_button = QPushButton("Connect && test")
        self.connect_button.setObjectName("primary")
        self.connection_stop = QPushButton("Stop")
        self.connection_stop.clicked.connect(self.cancel_request)
        self.load_key = QPushButton("Use remembered key")
        self.forget_key = QPushButton("Forget key")
        for item in (self.connect_button, self.connection_stop, self.load_key, self.forget_key):
            row.addWidget(item)
        form.addLayout(row)
        form.addWidget(
            text(
                "Connect tests one small synthetic request. Provider charges may apply. Keys stay local; remember is optional."
            )
        )
        layout.addWidget(self.connection)
        self.connection_summary = QWidget()
        connection_row = QHBoxLayout(self.connection_summary)
        connection_row.setContentsMargins(0, 0, 0, 0)
        self.connection_label = text("Not connected")
        self.change_connection = QPushButton("Connection settings")
        self.test_connection = QPushButton("Test connection")
        connection_row.addWidget(self.connection_label, 1)
        connection_row.addWidget(self.test_connection)
        connection_row.addWidget(self.change_connection)
        layout.addWidget(self.connection_summary)
        self.connection_summary.hide()
        outer_layout = layout
        self.chat_panel = QWidget()
        layout = QVBoxLayout(self.chat_panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        outer_layout.addWidget(self.chat_panel, 1)
        self.setup_space = QWidget()
        outer_layout.addWidget(self.setup_space, 1)
        self.conversation = QTextBrowser()
        self.conversation.setOpenExternalLinks(False)
        self.conversation.setOpenLinks(False)
        self.conversation.setAccessibleName("Assistant conversation and application action results")
        self.conversation.setMinimumHeight(120)
        layout.addWidget(self.conversation, 1)
        suggestions = QHBoxLayout()
        for label, question in [
            (
                "Check this computer",
                "Check this computer's diagnostic access. If permitted, collect evidence and analyze what it shows.",
            ),
            (
                "Explain my findings",
                "Read the current findings and explain what they mean and what I should do next.",
            ),
            ("Explore an example", "Open the synthetic example and explain its findings."),
        ]:
            button = QPushButton(label)
            button.clicked.connect(
                lambda checked=False, value=question: self.question.setPlainText(value)
            )
            suggestions.addWidget(button)
        layout.addLayout(suggestions)
        self.question = Composer()
        self.question.setPlaceholderText("Ask a question or tell me what to do in the app…")
        self.question.setAccessibleName("Chat message; Enter sends, Shift Enter adds a line")
        self.question.setMaximumHeight(85)
        self.question.setMinimumHeight(65)
        layout.addWidget(self.question)
        actions = QHBoxLayout()
        self.details_button = QPushButton("Details")
        self.open_output = QPushButton("Open output folder")
        self.open_output.setVisible(False)
        self.clear = QPushButton("New chat")
        self.cancel = QPushButton("Stop")
        self.send = QPushButton("Send")
        self.send.setObjectName("primary")
        for item in (self.details_button, self.open_output, self.clear):
            actions.addWidget(item)
        actions.addStretch()
        actions.addWidget(self.cancel)
        actions.addWidget(self.send)
        layout.addLayout(actions)
        self.details = QWidget()
        detail_layout = QVBoxLayout(self.details)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        self.allowance = text("")
        detail_layout.addWidget(self.allowance)
        detail_layout.addWidget(
            text(
                "AI can inspect redacted case summaries and run app diagnostics. Up to5 recent exchanges are sent for continuity; no raw case uploads or Windows setting changes. Each Send allows up to3 bounded provider calls and6 app actions. Disable or New chat clears memory. Calls can be billed even after cancellation."
            )
        )
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(100)
        self.preview.setAccessibleName("Last sent redacted request; no key or authorization header")
        detail_layout.addWidget(self.preview)
        self.reset = QPushButton("Reset request counter")
        detail_layout.addWidget(self.reset)
        layout.addWidget(self.details)
        self.details.hide()
        self.details_button.clicked.connect(
            lambda: self.details.setVisible(not self.details.isVisible())
        )
        self.change_connection.clicked.connect(self.toggle_connection)
        self.connect_button.clicked.connect(self.connect_provider)
        self.test_connection.clicked.connect(self.connect_provider)
        self.load_key.clicked.connect(self.load_remembered)
        self.forget_key.clicked.connect(self.forget)
        self.send.clicked.connect(self.send_request)
        self.question.submitted.connect(self.send_request)
        self.cancel.clicked.connect(self.cancel_request)
        self.clear.clicked.connect(self.clear_conversation)
        self.reset.clicked.connect(self.reset_allowance)
        self.open_output.clicked.connect(self.open_output_folder)
        self.provider.currentIndexChanged.connect(self.provider_changed)
        self.model.currentIndexChanged.connect(self.connection_changed)
        self.key.textEdited.connect(self.connection_changed)
        self.question.textChanged.connect(self.refresh_send)
        self.provider_changed()
        self.chat_panel.hide()
        self.append(
            "Assistant",
            "Hi! Connect your provider, then ask a question or give me a task. I can check access, collect and analyze evidence, explain findings, prepare reports and compare cases through this app.",
        )
        self.activity(False)

    def selected_provider(self) -> Provider:
        return Provider(self.provider.currentData())

    def provider_changed(self) -> None:
        self.key.clear()
        self.remember.setChecked(False)
        self.model.clear()
        for model in CHAT_MODELS:
            if model.provider == self.selected_provider():
                self.model.addItem(model.model, model.model)
        preferred = self.model.findData("gemini-3.5-flash-lite")
        if preferred >= 0:
            self.model.setCurrentIndex(preferred)
        self.connection_changed()

    def connection_changed(self) -> None:
        self.connected = False
        self.chat.connection = None
        self.chat.history.clear()
        self.connection_label.setText("Not connected")
        self.refresh_send()

    def toggle_connection(self) -> None:
        self.connection.setVisible(self.connection.isHidden())
        self.chat_panel.setVisible(self.connected and self.connection.isHidden())
        self.setup_space.setVisible(not self.chat_panel.isVisible())

    def connect_provider(self) -> None:
        if self.controller.busy or self.disabled:
            return
        provider = self.selected_provider()
        model = selected_model(provider, self.model.currentData())
        value, remember = self.key.text().strip(), self.remember.isChecked()
        self.mode_action = "connect"
        self.connected = False
        self.status.setText("Testing connection…")

        async def connect() -> object:
            if value:
                self.keys.set(provider, value, remember=remember)
            key = self.keys.get(provider)
            if key is None:
                raise AiFailure(AiErrorCode.CONFIGURATION)
            return await self.chat.connect(model, key, _test_transport=self._test_transport)

        self.controller.launch(connect)

    def load_remembered(self) -> None:
        if self.controller.busy:
            return
        provider = self.selected_provider()
        self.mode_action = "load"

        def load() -> object:
            if not self.keys.load_remembered(provider):
                raise AiFailure(AiErrorCode.CONFIGURATION)
            return "key_loaded"

        self.controller.call(load)

    def forget(self) -> None:
        if self.controller.busy:
            return
        provider = self.selected_provider()
        self.connection_changed()
        self.controller.call(lambda: self.keys.forget(provider))
        self.status.setText("Removing this app's remembered key…")

    def append(self, role: str, message: str) -> None:
        self.messages.append((role, message))
        del self.messages[:-80]
        body = "".join(
            "<p><b>"
            + html.escape(speaker)
            + "</b><br>"
            + html.escape(value).replace("\n", "<br>")
            + "</p>"
            for speaker, value in self.messages
        )
        self.conversation.setHtml(body)
        bar = self.conversation.verticalScrollBar()
        bar.setValue(bar.maximum())
        # Rich-text layout can update the range after setHtml returns. Keep the
        # newest action/result visible; QObject context cancels this on disposal.
        QTimer.singleShot(0, self.conversation, lambda: bar.setValue(bar.maximum()))

    def send_request(self) -> None:
        if not self.connected or self.controller.busy or self.disabled:
            return
        question = self.question.toPlainText().strip()
        if not question:
            return
        if len(question) > 4000:
            self.status.setText("Please keep each message within4000 characters.")
            return
        provider = self.selected_provider()
        model = selected_model(provider, self.model.currentData())
        key = self.keys.get(provider)
        if key is None:
            self.show_error(AiErrorCode.CONFIGURATION.value)
            return
        analysis = self.host_window.case_view.analysis
        index = self.host_window.case_view.result_index
        state = self.tools.snapshot()
        self.mode_action = "chat"
        try:
            shown_question = ChatPrivacy((key.reveal_for_request(),)).redact(question)
        except AiFailure as error:
            self.show_error(error.code.value)
            return
        self.append("You", shown_question)
        self.question.clear()

        async def chat() -> object:
            values = chain(
                (key.reveal_for_request(),),
                private_values(analysis) if analysis is not None else (),
                (value for page in index.iter_pages() for value in private_values(page))
                if index is not None
                else (),
            )
            privacy = ChatPrivacy(values)
            return await self.chat.chat(
                model,
                key,
                question,
                state,
                privacy,
                self.tools.execute,
                self.progress_message.emit,
                _test_transport=self._test_transport,
            )

        self.controller.launch(chat)

    def activity(self, busy: bool) -> None:
        if busy:
            self.phase_text = self.status.text()
            self.elapsed.start()
            self.wait_timer.start()
        else:
            self.wait_timer.stop()
        self.connection_stop.setEnabled(busy and not self.disabled)
        for item in (
            self.provider,
            self.model,
            self.key,
            self.remember,
            self.connect_button,
            self.test_connection,
            self.load_key,
            self.forget_key,
            self.reset,
        ):
            item.setEnabled(not busy and not self.disabled)
        self.clear.setEnabled(not busy and not self.disabled)
        self.cancel.setEnabled(busy and not self.disabled)
        self.refresh_send()

    def refresh_send(self) -> None:
        if hasattr(self, "send"):
            self.send.setEnabled(
                self.connected
                and not self.controller.busy
                and not self.disabled
                and bool(self.question.toPlainText().strip())
            )

    def status_message(self, value: str) -> None:
        self.phase_text = value
        self.status.setText(value)

    def show_wait(self) -> None:
        if self.controller.busy and self.elapsed.isValid():
            self.status.setText(f"{self.phase_text} · {self.elapsed.elapsed() // 1000}s")

    def completed(self, value: object, error: str) -> None:
        if self.disabled:
            self.keys.clear_session()
            self.chat.clear()
            return
        self.preview.setPlainText(self.chat.last_preview.decode("utf-8", errors="replace"))
        self.allowance.setText(
            f"{self.chat.allowance.attempts} provider requests this session. Provider limits apply; usage and final cost may be unknown."
        )
        if self.chat.records:
            record = self.chat.records[-1]
            self.allowance.setText(
                self.allowance.text()
                + f"\nLast request: {record.outcome} · {record.seconds:.1f}s · input {record.usage.input_tokens if record.usage.input_tokens is not None else 'unknown'} / output {record.usage.output_tokens if record.usage.output_tokens is not None else 'unknown'} tokens."
            )
        if error:
            self.show_error(error)
            return
        if value == "connected":
            self.connected = True
            self.key.clear()
            self.connection.hide()
            self.setup_space.hide()
            self.connection_summary.show()
            self.chat_panel.show()
            self.connection_label.setText(self.provider.currentText() + " · Connected")
            self.status.setText("Connected. Ask a question or give me an application task.")
        elif value == "key_loaded":
            self.status.setText(
                "Remembered key loaded locally. Choose Connect & test to verify it."
            )
        elif (
            isinstance(value, tuple)
            and len(value) == 2
            and isinstance(value[0], str)
            and isinstance(value[1], AiUsage)
        ):
            self.append("Assistant", value[0])
            self.status.setText("Ready")
        else:
            self.status.setText("Done")
        self.refresh_send()

    def tool_activity(self, name: str, result: object) -> None:
        if not isinstance(result, dict):
            return
        status = str(result.get("status", "unknown"))
        label = name.replace("_", " ").capitalize()
        code = result.get("code", "")
        self.append("App action", label + " · " + status + (" · " + str(code) if code else ""))
        if self.tools.artifacts:
            self.open_output.setVisible(True)

    def show_error(self, code: str) -> None:
        message = ERRORS.get(
            code,
            "The assistant could not finish this request. Your diagnostic results are unchanged.",
        )
        self.status.setText(message)
        self.append("Assistant", message)
        if self.mode_action == "connect":
            self.connected = False
            self.connection_label.setText("Connection not verified")
        self.refresh_send()

    def invalidate(self) -> None:
        # An assistant-owned operation is allowed to update the current case. A
        # user's unrelated context change cancels pending network work, not history typing.
        if self.tools.busy:
            return
        if self.controller.busy and self.mode_action == "chat":
            self.controller.invalidate()
        self.chat.history.clear()

    def cancel_request(self) -> None:
        self.controller.invalidate()
        self.tools.cancel()
        self.status.setText("Stopping… Completed application actions are retained.")

    def clear_conversation(self) -> None:
        self.chat.history.clear()
        self.messages.clear()
        self.conversation.clear()
        self.append("Assistant", "New conversation. What would you like help with?")

    def reset_allowance(self) -> None:
        self.chat.allowance.reset()
        self.allowance.setText("Request counter reset. Provider usage is unchanged.")

    def open_output_folder(self) -> None:
        for path in reversed(self.tools.artifacts):
            if path.is_file():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))
                return

    def disable(self) -> None:
        if self.disabled:
            return
        self.disabled = True
        self.controller.invalidate()
        self.tools.cancel()
        self.keys.clear_session()
        self.chat.clear()
        self.question.clear()
        self.key.clear()
        self.messages.clear()
        self.conversation.clear()
        self.preview.clear()
        self.connected = False
        self.activity(False)
