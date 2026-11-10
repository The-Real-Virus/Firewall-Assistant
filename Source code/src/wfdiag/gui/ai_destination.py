"""Lightweight disabled destination. Importing it never loads AI or HTTPX."""

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

if TYPE_CHECKING:
    from wfdiag.ai.service import AiSession
    from wfdiag.gui.ai_view import AiView
    from wfdiag.gui.main_window import MainWindow


class AiDestination(QWidget):
    def __init__(self, window: "MainWindow") -> None:
        super().__init__()
        self.host_window = window
        self.view: AiView | None = None
        self.session: AiSession | None = None
        self.disabling = False
        self.layout_box = QVBoxLayout(self)
        self.layout_box.setContentsMargins(32, 28, 32, 24)
        title = QLabel("AI Assistant")
        title.setObjectName("title")
        header = QHBoxLayout()
        header.addWidget(title, 1)
        self.notice = QLabel(
            "Ask questions and let the assistant use this app's diagnostics. AI is optional; the complete diagnostic engine works offline without a key."
        )
        self.notice.setTextFormat(Qt.TextFormat.PlainText)
        self.notice.setWordWrap(True)
        self.toggle = QPushButton("Enable AI")
        self.toggle.setAccessibleName("Enable optional cloud AI for this session")
        self.toggle.clicked.connect(self.toggle_enabled)
        header.addWidget(self.toggle)
        self.layout_box.addLayout(header)
        self.layout_box.addWidget(self.notice)
        back = QPushButton("Continue with diagnostics")
        back.clicked.connect(lambda: window.navigate(0))
        self.back = back
        self.layout_box.addWidget(back)
        self.layout_box.addStretch()

    def toggle_enabled(self) -> None:
        if self.view is not None:
            self.disable()
            return
        try:
            from wfdiag.gui.ai_view import AiView

            view = AiView(self.host_window, self.session)
        except Exception:  # noqa: BLE001 -- optional initialization never breaks diagnostics.
            self.notice.setText(
                "AI could not initialize. Diagnostics remain available. Check the optional installation; no request was sent."
            )
            return
        self.view = view
        self.session = view.controller.session
        self.layout_box.insertWidget(self.layout_box.count() - 2, view, 1)
        self.toggle.setText("Disable AI")
        self.back.hide()
        self.host_window.ai_status_label.setText("AI is on")
        self.notice.setText(
            "Application access enabled. Connect your provider, then chat. Shared summaries are redacted; API calls may cost. Windows settings stay unchanged."
        )

    def invalidate(self) -> None:
        if self.view is not None:
            self.view.invalidate()

    def disable(self) -> None:
        if self.view is None:
            return
        self.disabling = True
        self.toggle.setEnabled(False)
        self.view.disable()
        self.host_window.ai_status_label.setText("AI is off")
        if self.view.controller.busy:
            self.notice.setText(
                "AI is off. Cancellation requested; waiting for the bounded request cleanup. Diagnostics remain available."
            )
            QTimer.singleShot(20, self.disable)
            return
        self.layout_box.removeWidget(self.view)
        self.view.deleteLater()
        self.view = None
        self.disabling = False
        self.toggle.setEnabled(True)
        self.toggle.setText("Enable AI")
        self.back.show()
        self.notice.setText(
            "AI is off. Session keys and conversation references were cleared. Remembered Windows credentials remain until explicitly forgotten; revocation is a provider action. Cancellation does not prove a request was free or erase provider data."
        )

    def shutdown(self) -> bool:
        if self.view is None:
            return True
        self.disable()
        return self.view is None
