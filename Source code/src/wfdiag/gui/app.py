"""Windowed entry point with no collector, AI client or worker at startup."""

import sys
from pathlib import Path


def main(*, startup_check_root: Path | None = None) -> int:
    try:
        from PySide6.QtCore import QLockFile, QTimer
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import QApplication, QMessageBox

        from wfdiag.gui.controller import default_work_root, prepare_work_root
        from wfdiag.gui.main_window import MainWindow
        from wfdiag.gui.preferences import Preferences, PreferenceStore
        from wfdiag.gui.theme import apply_theme
        from wfdiag.storage.atomic_write import check_plain_path
        from wfdiag.storage.opened_files import OpenedDirectory
        from wfdiag.storage.private_output import verify_private_directory
    except ImportError:
        from wfdiag.gui.launcher import startup_error

        startup_error("GUI_IMPORT_FAILED", diagnostic=startup_check_root is not None)
        return 3
    app = QApplication(sys.argv)
    app.setApplicationName("Firewall Assistant")
    app.setOrganizationName("WFDiag")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    held = None
    lock = None
    try:
        root = startup_check_root if startup_check_root is not None else default_work_root()
        if startup_check_root is not None and (root.exists() or root.is_symlink()):
            return 2
        prepare_work_root(root)
        held = verify_private_directory(root)
        lock_path = root / ".application-instance.lock"
        check_plain_path(lock_path, allow_missing_leaf=True)
        if lock_path.exists():
            directory = OpenedDirectory(root)
            try:
                with directory.open_relative(lock_path.name):
                    pass
            finally:
                directory.close()
        lock = QLockFile(str(lock_path))
        lock.setStaleLockTime(0)
        if not lock.tryLock(0):
            if startup_check_root is not None:
                return 2
            QMessageBox.information(
                None,
                "Firewall Assistant is already open",
                "Another desktop instance owns this user's private application location. Use that window or close it before starting another.",
            )
            return 2
        store = PreferenceStore(root)
        warning = ""
        try:
            preferences = store.load()
        except (OSError, ValueError):
            preferences = Preferences()
            warning = "Private preferences could not be read. Safe defaults and history off are active; the old file was retained. No AI was enabled."
        apply_theme(app, preferences.theme)
        window = MainWindow(preferences, store)
        window.show()
        if startup_check_root is not None:
            from wfdiag.gui.launcher import emit_startup_check

            # Run the actual frozen imports, native platform plugin, private root,
            # instance lock, resource loading, event loop and background example.
            # No collector, API client, credential store or external URL is invoked.
            window.open_example()
            attempts = 0

            def check_ready() -> None:
                nonlocal attempts
                attempts += 1
                if not window.example_open and attempts < 100:
                    QTimer.singleShot(50, check_ready)
                    return
                analysis = window.case_view.analysis
                checks = {
                    "window_visible": window.isVisible(),
                    "window_rendered": not window.grab().isNull(),
                    "icon_loaded": not window.windowIcon().isNull(),
                    "synthetic_example_loaded": window.example_open and analysis is not None,
                    "ai_off": window.ai_destination.view is None
                    and window.ai_destination.session is None
                    and window.ai_status_label.text() == "AI is off",
                    "history_off": not window.preferences.value.history_enabled,
                }
                emit_startup_check(checks)
                window.close()
                app.exit(0 if all(checks.values()) else 6)

            QTimer.singleShot(100, check_ready)
        if warning:
            window.statusBar().showMessage(warning)
        return app.exec()
    except (OSError, ValueError):
        if startup_check_root is not None:
            return 4
        QMessageBox.critical(
            None,
            "Private application storage unavailable",
            "The private per-user application location could not be verified. No evidence was collected. Resolve its permissions or use the independent CLI with an approved private work location.",
        )
        return 4
    finally:
        if lock is not None:
            lock.unlock()
        if held is not None:
            held.close()


if __name__ == "__main__":
    raise SystemExit(main())
