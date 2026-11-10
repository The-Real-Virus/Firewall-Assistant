from collections.abc import Iterator
from itertools import pairwise

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot

from wfdiag.gui.main_window import AUTHOR_LINKS, MainWindow


@pytest.fixture
def window(qtbot: QtBot) -> Iterator[MainWindow]:
    widget = MainWindow()
    qtbot.addWidget(widget)
    widget.show()
    yield widget
    widget.close()


def test_open_example_navigates_to_plain_synthetic_findings(
    window: MainWindow, qtbot: QtBot
) -> None:
    target = next(b for b in window.findChildren(QPushButton) if b.text() == "Open &example")
    qtbot.mouseClick(target, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.example_open)
    assert window.example_open
    assert window.pages.currentIndex() == 2
    assert window.table.model().rowCount() > 0
    assert window.case_tabs.currentIndex() == 0


def test_live_operations_cannot_fake_success(window: MainWindow) -> None:
    controls = {b.text(): b for b in window.findChildren(QPushButton)}
    assert controls["Open case folder"].isEnabled()
    assert controls["Check access only"].isEnabled()
    assert not controls["Export share report"].isEnabled()  # No validated analysis yet.
    assert controls["Collect local evidence"].isEnabled()
    assert not controls["Analyze collected case"].isEnabled()
    assert window.ai_destination.toggle.isEnabled()
    assert window.ai_destination.view is None
    assert not window.controller.busy and window.controller.jobs is None


def test_ai_is_separate_and_disabled_without_setup(window: MainWindow, qtbot: QtBot) -> None:
    qtbot.mouseClick(window.nav_buttons["AI Assistant"], Qt.MouseButton.LeftButton)
    assert window.pages.currentIndex() == 5
    target = next(
        b for b in window.findChildren(QPushButton) if b.text() == "Continue with diagnostics"
    )
    qtbot.mouseClick(target, Qt.MouseButton.LeftButton)
    assert window.pages.currentIndex() == 0


def test_minimum_window_reflows_detail_below_list(window: MainWindow, qtbot: QtBot) -> None:
    window.resize(1000, 700)
    qtbot.waitUntil(lambda: window.finding_splitter.orientation() == Qt.Orientation.Vertical)
    assert window.rail.width() == 168
    assert window.minimumWidth() == 1000


@pytest.mark.parametrize("theme", ["Light", "Dark", "System", "High contrast"])
def test_theme_switch_preserves_selection(window: MainWindow, qtbot: QtBot, theme: str) -> None:
    window.open_example()
    qtbot.waitUntil(lambda: window.example_open)
    window.set_theme(theme)
    assert window.pages.currentIndex() == 2
    assert window.theme_selection == theme
    assert window.table.currentIndex().row() == 0


@pytest.mark.parametrize("theme", ["Light", "Dark", "High contrast"])
def test_author_footer_preserves_order_and_fits_minimum_window(
    window: MainWindow, qtbot: QtBot, theme: str
) -> None:
    window.set_theme(theme)
    window.resize(1000, 700)
    qtbot.waitUntil(lambda: window.rail.width() == 168)
    widgets = [
        window.nav_buttons["Settings"],
        window.nav_buttons["AI Assistant"],
        window.version_label,
        window.ai_status_label,
        window.maker_label,
        window.profile_buttons["GitHub"],
        window.copyright_label,
    ]
    positions = [item.mapTo(window.rail, QPoint(0, 0)).y() for item in widgets]
    assert all(left < right for left, right in pairwise(positions))
    assert positions[-1] + window.copyright_label.height() <= window.rail.height()
    assert window.maker_label.text() == "Made By ViRuS"
    assert window.ai_status_label.text() == "AI is off"
    assert "© 2026 ViRuS." in window.copyright_label.text()
    assert "All rights reserved." in window.copyright_label.text()
    assert not any(item.icon().isNull() for item in window.profile_buttons.values())


@pytest.mark.parametrize("site", ["GitHub", "LinkedIn"])
def test_profile_icons_open_only_the_owner_supplied_url_on_click(
    window: MainWindow, qtbot: QtBot, monkeypatch: pytest.MonkeyPatch, site: str
) -> None:
    opened: list[str] = []
    monkeypatch.setattr(
        QDesktopServices, "openUrl", lambda url: opened.append(url.toString()) or True
    )
    window.set_theme("Dark")
    assert not opened
    qtbot.mouseClick(window.profile_buttons[site], Qt.MouseButton.LeftButton)
    assert opened == [AUTHOR_LINKS[site]]
    assert "browser" in window.profile_buttons[site].accessibleName()


def test_profile_navigation_failure_is_reported_without_fallback(
    window: MainWindow, qtbot: QtBot, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: False)
    qtbot.mouseClick(window.profile_buttons["GitHub"], Qt.MouseButton.LeftButton)
    assert "Could not open the GitHub profile" in window.statusBar().currentMessage()
