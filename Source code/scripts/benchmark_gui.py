"""Synthetic source Qt measurements only; never native/private/frozen acceptance.

Run against the exact 100000-finding output from benchmark_analysis.py. Does not
start app.main, preferences I/O, collectors, workers, credentials, AI or networking.
The outer caller must retain the command/platform/source fingerprints (run_check.py).
"""

import argparse
import hashlib
import json
import math
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from benchmark_analysis import host_facts, memory_counters

EXPECTED_SHA256 = "c5a82325a8e17c85de325a780d9225fa0acb5404ebcd2d05722c70cd575776d3"
ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--idle-seconds", type=int, choices=(0, 60), default=0)
    parser.add_argument("--cycles", type=int, choices=(1, 20), default=1)
    parser.add_argument("--_child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.analysis = args.analysis.absolute()
    if sys.platform != "win32":
        parser.error("This source probe uses Windows process metrics")
    with args.analysis.open("rb") as stream:
        if os.fstat(stream.fileno()).st_size > 128 * 1024 * 1024:
            parser.error("Synthetic analysis exceeds its byte cap")
        if hashlib.file_digest(stream, "sha256").hexdigest() != EXPECTED_SHA256:
            parser.error("Only the exact recorded invented 100000-finding fixture is permitted")
    if not args._child:
        from wfdiag.collectors.process_runner import _bounded_process
        from wfdiag.services.cancellation import CancellationToken

        result = _bounded_process(
            [
                str(Path(sys.executable).resolve()),
                str(Path(__file__).resolve()),
                *sys.argv[1:],
                "--_child",
            ],
            cwd=ROOT,
            cancellation=CancellationToken(),
            timeout=900 if args.cycles == 20 else 180,
            output_limit=256 * 1024,
            environment={**os.environ, "QT_QPA_PLATFORM": "offscreen", "PYTHONUTF8": "1"},
        )
        print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
        print(result.stderr.decode("utf-8", errors="replace"), end="", file=sys.stderr, flush=True)
        return int(
            bool(
                result.return_code
                or result.timed_out
                or result.cancelled
                or result.output_truncated
                or result.read_failed
            )
        )
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QFont, QFontDatabase
    from PySide6.QtWidgets import QApplication

    from wfdiag.gui.main_window import MainWindow
    from wfdiag.gui.preferences import Preferences
    from wfdiag.gui.theme import apply_theme
    from wfdiag.storage.analysis_index import AnalysisIndex, read_gui_analysis

    app = QApplication([])
    app.setStyle("Fusion")
    if not QFontDatabase.families():
        for filename in ("segoeui.ttf", "segoeuib.ttf", "seguisb.ttf"):
            QFontDatabase.addApplicationFont(str(Path(os.environ["WINDIR"]) / "Fonts" / filename))
    app.setFont(QFont("Segoe UI", 10))
    apply_theme(app, "Dark")
    window = MainWindow(Preferences(theme="Dark"))
    window.show()

    def load_failed(value, error):
        if error:
            print("COMPONENT_LOCAL_LOAD_FAILED:" + error, flush=True)
            app.exit(1)

    window.controller.loaded.connect(load_failed)
    started = time.perf_counter()
    phase = "initial"
    last = started
    load_started = started
    measurements: list[dict[str, object]] = []
    heartbeats: list[dict[str, object]] = []
    latencies: list[dict[str, object]] = []
    cycle = 0
    position = 0
    idle_started = 0.0
    idle_cpu = 0.0
    idle_result: dict[str, object] | None = None
    directory = (
        ROOT / ".build" / ("gui-component-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ"))
    )
    directory.mkdir()
    heartbeat = QTimer(window)
    heartbeat.setInterval(10)

    def save_status(state="running"):
        target = directory / "status.json"
        temporary = directory / "status.json.tmp"
        temporary.write_text(
            json.dumps(
                {
                    "state": state,
                    "phase": phase,
                    "completed_cycles": cycle,
                    "interactions_completed": len(latencies),
                    "updated_at_utc": datetime.now(UTC).isoformat(),
                    "acceptance": "source component observation only; incomplete run never passes",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)

    def safe(callback):
        def wrapped():
            try:
                callback()
            except Exception as error:  # noqa: BLE001 -- fail the probe on any callback error.
                # Never emit arbitrary input/exception strings.
                save_status("failed")
                print("COMPONENT_PROBE_FAILED:" + type(error).__name__, flush=True)
                app.exit(1)

        return wrapped

    def pulse():
        nonlocal last
        now = time.perf_counter()
        heartbeats.append(
            {"seconds": now - started, "interval_ms": (now - last) * 1000, "phase": phase}
        )
        last = now

    heartbeat.timeout.connect(pulse)

    def finish():
        heartbeat.stop()
        result = {
            "scope": "synthetic source offscreen Qt component only; no app.main/private/frozen/reference acceptance",
            "analysis_sha256": EXPECTED_SHA256,
            "findings": window.case_view.total_findings,
            "interaction_count": len(latencies),
            "interactions": latencies,
            "interaction_p95_ms": sorted(float(item["milliseconds"]) for item in latencies)[
                math.ceil(len(latencies) * 0.95) - 1
            ],
            "maximum_heartbeat_interval_ms": max(float(item["interval_ms"]) for item in heartbeats),
            "heartbeats": heartbeats,
            "cycles": measurements,
            "cycle_retained_growth_bytes": int(measurements[-1]["working_set_bytes"])
            - int(measurements[0]["working_set_bytes"]),
            "idle": idle_result,
            "component_memory": memory_counters(),
            "host": host_facts(),
            "cache_state": "uncontrolled/warm; fixture SHA read before measurement",
            "page_timing": "includes background page read completion and actual grab repaint; other actions include actual repaint",
            "ai_enabled": window.ai_destination.view is not None,
            "native_private_collector_network_credentials_frozen_reference": "not_executed; required acceptance blocked",
        }
        (directory / "result.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        save_status("completed")
        print(
            json.dumps(
                {k: v for k, v in result.items() if k not in ("heartbeats", "interactions")}
            ),
            flush=True,
        )
        print("RECORD=" + (directory / "result.json").relative_to(ROOT).as_posix(), flush=True)
        window.close()
        app.quit()

    def idle_end():
        nonlocal idle_result
        duration = time.perf_counter() - idle_started
        if duration < args.idle_seconds:
            QTimer.singleShot(math.ceil((args.idle_seconds - duration) * 1000), safe(idle_end))
            return
        cpu_seconds = time.process_time() - idle_cpu
        idle_result = {
            "duration_seconds": duration,
            "cpu_seconds": cpu_seconds,
            "one_core_cpu_percent": cpu_seconds / duration * 100,
            "logical_processor_normalized_cpu_percent": cpu_seconds
            / duration
            / (os.cpu_count() or 1)
            * 100,
            **memory_counters(),
            "method": "process CPU delta / wall time; one-core and logical-processor-normalized values both retained; no other process included",
        }
        finish()

    def after_cycles():
        nonlocal phase, idle_started, idle_cpu
        if args.idle_seconds:
            phase = "idle"
            # Stop the probe's10ms heartbeat so it does not manufacture idle CPU.
            heartbeat.stop()
            save_status()
            idle_started, idle_cpu = time.perf_counter(), time.process_time()
            QTimer.singleShot(args.idle_seconds * 1000, safe(idle_end))
        else:
            finish()

    def interact():
        nonlocal position, phase
        if position == 100:
            save_status()
            QTimer.singleShot(100, safe(begin if cycle < args.cycles else after_cycles))
            return
        action = position % 5
        phase = ("page", "tab", "reveal", "resize", "selection")[action]
        start = time.perf_counter()
        if action == 0:
            window.case_view.load_page((position * 17) % 200)
        elif action == 1:
            window.case_tabs.setCurrentIndex(1 if (position // 5) % 2 else 0)
        elif action == 2:
            window.case_view.reveal.setChecked(not window.case_view.reveal.isChecked())
        elif action == 3:
            window.resize(1000, 700) if (position // 5) % 2 else window.resize(1280, 840)
        else:
            window.table.selectRow(min((position * 3) % 20, window.table.model().rowCount() - 1))

        def painted():
            nonlocal position
            if window.controller.busy:
                QTimer.singleShot(1, safe(painted))
                return
            if action == 0:
                assert window.case_view.page_index == (position * 17) % 200
            assert not window.grab().isNull()
            latencies.append(
                {"action": phase, "milliseconds": (time.perf_counter() - start) * 1000}
            )
            position += 1
            QTimer.singleShot(30, safe(interact))

        painted()

    def loaded(value):
        nonlocal phase, cycle
        assert isinstance(value, AnalysisIndex) and value.count == 100000
        phase = "binding"
        window.controller.bind(value, None, synthetic=True)
        cycle += 1
        phase = "loaded"
        observation = {
            "cycle": cycle,
            "load_seconds": time.perf_counter() - load_started,
            **memory_counters(),
        }
        measurements.append(observation)
        save_status()
        print(json.dumps(observation), flush=True)
        QTimer.singleShot(
            100, safe(interact if cycle == 1 else begin if cycle < args.cycles else after_cycles)
        )

    def begin():
        nonlocal load_started, last, phase
        # Model replacement closes the old held file. Capture is a repeated result
        # open/replace cycle in one source window, not20 process/OS launches.
        phase = "background-load"
        save_status()
        last = time.perf_counter()
        if not heartbeat.isActive():
            heartbeat.start()
        load_started = time.perf_counter()
        window.controller.run_local(lambda: read_gui_analysis(args.analysis), loaded)

    def timeout():
        save_status("watchdog_expired")
        print("COMPONENT_PROBE_WATCHDOG_EXPIRED", flush=True)
        app.exit(1)

    QTimer.singleShot(900000 if args.cycles == 20 else 150000, timeout)
    QTimer.singleShot(300, safe(begin))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
