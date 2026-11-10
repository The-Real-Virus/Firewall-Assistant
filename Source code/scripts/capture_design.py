"""Capture the actual Qt development shell with synthetic data; never collect host evidence."""

import argparse
import json
import os
from pathlib import Path

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import QTimer, qVersion
from PySide6.QtGui import QFont, QFontDatabase, QFontMetrics
from PySide6.QtWidgets import QApplication

from wfdiag.gui.main_window import MainWindow


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--ai-only",
        action="store_true",
        help="Capture optional AI layout using a local prepared preview; no key or send",
    )
    parser.add_argument(
        "--workspace-only",
        action="store_true",
        help="Capture bounded findings/evidence and settings using bundled synthetic data",
    )
    args = parser.parse_args()
    if args.ai_only and args.workspace_only:
        parser.error("Choose one capture set")
    args.out.mkdir(parents=True, exist_ok=False)
    app = QApplication([])
    app.setStyle("Fusion")
    font_fallback = False
    if not QFontDatabase.families():
        font_root = Path(os.environ["WINDIR"]) / "Fonts"
        for font_file in ("segoeui.ttf", "segoeuib.ttf", "seguisb.ttf"):
            QFontDatabase.addApplicationFont(str(font_root / font_file))
        font_fallback = True
    app.setFont(QFont("Segoe UI", 10))
    if not QFontMetrics(app.font()).inFontUcs4(ord("A")):
        raise RuntimeError("Capture font cannot render basic Latin text")
    window = MainWindow()
    window.show()
    snapshots = [
        ("overview-light", "Light", 0, 1280, 840),
        ("findings-dark", "Dark", 2, 1280, 840),
        ("findings-light", "Light", 2, 1280, 840),
        ("minimum-dark", "Dark", 2, 1000, 700),
        ("diagnose-dark", "Dark", 1, 1280, 840),
        ("diagnose-minimum-light", "Light", 1, 1000, 700),
        ("ai-disabled-dark", "Dark", 5, 1280, 840),
    ]
    if args.ai_only:
        snapshots = [
            ("ai-disabled-dark", "Dark", 5, 1280, 840),
            ("ai-config-light", "Light", 5, 1280, 840),
            ("ai-config-minimum-dark", "Dark", 5, 1000, 700),
            ("ai-review-light", "Light", 5, 1280, 840),
            ("ai-review-minimum-dark", "Dark", 5, 1000, 700),
        ]
    elif args.workspace_only:
        snapshots = [
            ("findings-light", "Light", 2, 1280, 840),
            ("findings-minimum-dark", "Dark", 2, 1000, 700),
            ("evidence-light", "Light", 2, 1280, 840),
            ("evidence-minimum-dark", "Dark", 2, 1000, 700),
            ("settings-light", "Light", 4, 1280, 840),
            ("settings-minimum-dark", "Dark", 4, 1000, 700),
        ]
    index = 0

    def capture() -> None:
        nonlocal index
        if index:
            previous = snapshots[index - 1][0]
            if not window.grab().save(str(args.out / f"{previous}.png")):
                raise RuntimeError("Qt screenshot write failed")
        if index == len(snapshots):
            metadata = {
                "synthetic": True,
                "engine_backed_views": True,
                "example_source": "bundled analysis verified against the shared engine",
                "desktop_job_worker_executed_during_capture": False,
                "local_bundled_example_loading_task": not args.ai_only,
                "private_preferences_store_used": False,
                "workspace_layout_only": args.workspace_only,
                "platform_plugin": app.platformName(),
                "pyside": pyside_version,
                "qt": qVersion(),
                "device_pixel_ratio": window.devicePixelRatioF(),
                "images": [s[0] + ".png" for s in snapshots],
                "native_accessibility_validated": False,
                "ai_layout_only": args.ai_only,
                "ai_preview": "local built-in general-help prepared object; no key, HTTPX client, worker or send"
                if args.ai_only
                else None,
                "registered_existing_system_fonts_for_offscreen_capture": font_fallback,
            }
            (args.out / "capture.json").write_text(
                json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
            )
            app.quit()
            return
        name, theme, page, width, height = snapshots[index]
        window.set_theme(theme)
        window.resize(width, height)
        window.open_example() if page == 2 else window.navigate(page)
        if args.workspace_only and name.startswith("evidence"):

            def evidence() -> None:
                window.case_tabs.setCurrentIndex(1)
                window.case_view.reveal.setChecked(False)

            QTimer.singleShot(100, evidence)
        if args.ai_only and "disabled" not in name:
            if window.ai_destination.view is None:
                window.ai_destination.toggle_enabled()
            view = window.ai_destination.view
            assert view is not None
            view.provider.setCurrentIndex(1)
            if "review" in name:
                from wfdiag.ai.context import general_request
                from wfdiag.ai.contracts import AiConfiguration
                from wfdiag.ai.models import MODELS
                from wfdiag.ai.policy import DisclosurePolicy, context_revision
                from wfdiag.ai.service import prepare

                model = MODELS[0]
                prepared = prepare(
                    AiConfiguration(enabled=True, provider=model.provider, model=model.model),
                    general_request("profiles"),
                    context_revision("capture-general-help"),
                    DisclosurePolicy(),
                )
                view.completed(prepared, "")
                QTimer.singleShot(100, lambda: view.ensureWidgetVisible(view.send))
            else:
                view.verticalScrollBar().setValue(0)
        index += 1
        QTimer.singleShot(300, capture)

    QTimer.singleShot(300, capture)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
