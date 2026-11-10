"""One local token set for light/dark design; system high contrast stays native."""

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


@dataclass(frozen=True)
class Theme:
    background: str
    surface: str
    raised: str
    text: str
    secondary: str
    border: str
    control_border: str
    accent: str
    accent_text: str
    focus: str
    warning: str


LIGHT = Theme(
    "#F4F7FB",
    "#FFFFFF",
    "#EDF2F8",
    "#172033",
    "#475569",
    "#CBD5E1",
    "#7A879B",
    "#1D4ED8",
    "#FFFFFF",
    "#1D4ED8",
    "#92400E",
)
DARK = Theme(
    "#0B1220",
    "#111C2E",
    "#18263B",
    "#E8EEF8",
    "#A7B7CE",
    "#34445E",
    "#6B7F9E",
    "#93C5FD",
    "#0B1220",
    "#BFDBFE",
    "#FBBF77",
)


def stylesheet(theme: Theme) -> str:
    return f"""
    QWidget {{ color: {theme.text}; font-family: 'Segoe UI'; font-size: 14px; }}
    QMainWindow, QStackedWidget, QScrollArea, QWidget#page {{ background: {theme.background}; }}
    QFrame#rail, QFrame#panel, QTabWidget::pane {{ background: {theme.surface}; border: 1px solid {theme.border}; border-radius: 12px; }}
    QFrame#rail {{ border: none; border-right: 1px solid {theme.border}; border-radius: 0; }}
    QLabel#title {{ font-size: 26px; font-weight: 600; }}
    QLabel#section {{ font-size: 18px; font-weight: 600; }}
    QLabel#brand {{ font-size: 18px; font-weight: 700; }}
    QLabel#muted {{ color: {theme.secondary}; }}
    QLabel#footerMeta {{ color: {theme.secondary}; font-size: 12px; }}
    QLabel#watermark {{ color: {theme.secondary}; font-size: 12px; font-weight: 600; }}
    QLabel#copyright {{ color: {theme.secondary}; font-size: 11px; }}
    QLabel#warning {{ color: {theme.warning}; }}
    QLabel#badge {{ color: {theme.accent}; background: {theme.raised}; border-radius: 8px; padding: 8px 12px; }}
    QPushButton {{ background: {theme.surface}; border: 1px solid {theme.control_border}; border-radius: 8px; min-height: 36px; padding: 0 14px; }}
    QPushButton:hover {{ background: {theme.raised}; }}
    QToolButton#profileLink {{ background: transparent; border: 1px solid {theme.control_border}; border-radius: 8px; padding: 4px; }}
    QToolButton#profileLink:hover {{ background: {theme.raised}; }}
    QToolButton#profileLink:focus {{ border: 2px solid {theme.focus}; }}
    QPushButton:focus, QLineEdit:focus, QComboBox:focus, QTableView:focus {{ border: 2px solid {theme.focus}; }}
    QPushButton#primary {{ background: {theme.accent}; color: {theme.accent_text}; border: none; font-weight: 600; min-height: 40px; }}
    QPushButton#primary:focus {{ border: 2px dashed {theme.accent_text}; }}
    QPushButton#nav {{ background: transparent; border: none; text-align: left; min-height: 42px; padding: 0 16px; }}
    QPushButton#nav:checked {{ background: {theme.raised}; color: {theme.accent}; font-weight: 600; border-left: 3px solid {theme.accent}; border-radius: 8px; }}
    QPushButton#nav:focus {{ border: 2px solid {theme.focus}; }}
    QPushButton:disabled {{ color: {theme.secondary}; background: {theme.raised}; }}
    QPushButton#primary:disabled {{ color: {theme.secondary}; background: {theme.raised}; }}
    QLineEdit, QComboBox {{ background: {theme.surface}; border: 1px solid {theme.control_border}; border-radius: 8px; min-height: 36px; padding: 0 10px; }}
    QPlainTextEdit {{ background: {theme.surface}; border: 1px solid {theme.control_border}; color: {theme.text}; padding: 8px; }}
    QTableView {{ background: {theme.surface}; alternate-background-color: {theme.raised}; border: 1px solid {theme.control_border}; gridline-color: {theme.border}; selection-background-color: {theme.raised}; selection-color: {theme.text}; }}
    QListView {{ background: {theme.surface}; color: {theme.text}; border: 1px solid {theme.control_border}; selection-background-color: {theme.raised}; selection-color: {theme.text}; }}
    QHeaderView, QTableCornerButton::section {{ background: {theme.surface}; border: none; }}
    QHeaderView::section {{ background: {theme.surface}; color: {theme.secondary}; border: none; border-bottom: 1px solid {theme.border}; padding: 12px 8px; text-align: left; }}
    QTabBar::tab {{ background: transparent; color: {theme.secondary}; padding: 16px 20px; border-bottom: 2px solid {theme.border}; }}
    QTabBar::tab:selected {{ color: {theme.accent}; border-bottom: 3px solid {theme.accent}; }}
    QSplitter::handle {{ background: {theme.background}; width: 16px; }}
    QCheckBox {{ spacing: 8px; }}
    """


def apply_theme(app: QApplication, selection: str) -> None:
    original = app.property("wfdiagSystemPalette")
    if not isinstance(original, QPalette):
        original = QPalette(app.palette())
        app.setProperty("wfdiagSystemPalette", original)
    if selection == "High contrast":
        app.setStyleSheet("")
        app.setPalette(original)
        return
    dark = selection == "Dark" or (
        selection == "System" and app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    )
    theme = DARK if dark else LIGHT
    palette = QPalette(original)
    # Native subcontrols such as scrollbars and unused header space also need the
    # selected palette; stylesheet sections alone leave bright light-mode patches.
    for role, color in (
        (QPalette.ColorRole.Window, theme.background),
        (QPalette.ColorRole.WindowText, theme.text),
        (QPalette.ColorRole.Base, theme.surface),
        (QPalette.ColorRole.AlternateBase, theme.raised),
        (QPalette.ColorRole.Text, theme.text),
        (QPalette.ColorRole.Button, theme.surface),
        (QPalette.ColorRole.ButtonText, theme.text),
        (QPalette.ColorRole.Highlight, theme.accent),
        (QPalette.ColorRole.HighlightedText, theme.accent_text),
        (QPalette.ColorRole.ToolTipBase, theme.surface),
        (QPalette.ColorRole.ToolTipText, theme.text),
        (QPalette.ColorRole.Light, theme.raised),
        (QPalette.ColorRole.Mid, theme.control_border),
        (QPalette.ColorRole.Dark, theme.control_border),
        (QPalette.ColorRole.Shadow, theme.control_border),
    ):
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet(stylesheet(theme))
