"""Lightweight desktop launcher with a Qt-independent failure message."""

import ctypes
import json
import sys
from pathlib import Path

MESSAGES = {
    "GUI_IMPORT_FAILED": "The desktop runtime could not load. Extract the complete application folder, including _internal, and contact the maintainer with this code.",
    "GUI_STARTUP_FAILED": "The desktop could not start. Contact the maintainer with this code. No diagnostic collection was requested.",
    "GUI_ARGUMENTS_INVALID": "Use FirewallAssistant.exe to open the desktop. The startup check requires a new absolute directory path.",
}


def startup_error(code: str, *, diagnostic: bool = False) -> None:
    """Only fixed messages leave startup; never echo exceptions, paths or case data."""
    message = f"{MESSAGES[code]}\n\nSupport code: {code}"
    if sys.stderr is not None:
        print(message, file=sys.stderr, flush=True)
    elif sys.platform == "win32" and not diagnostic:
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.MessageBoxW.argtypes = (
                ctypes.c_void_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_uint,
            )
            user32.MessageBoxW.restype = ctypes.c_int
            user32.MessageBoxW(None, message, "Firewall Assistant could not start", 0x10)
        except OSError:
            pass


def main() -> int:
    args = sys.argv[1:]
    diagnostic = bool(args)
    root = None
    if args:
        try:
            from wfdiag.contracts.base import absolute_local_path

            if len(args) != 2 or args[0] != "--startup-check":
                raise ValueError("Invalid startup check arguments")
            root = Path(absolute_local_path(args[1]))
            if root.exists() or root.is_symlink():
                raise ValueError("Startup checks require a new directory")
        except (OSError, ValueError):
            startup_error("GUI_ARGUMENTS_INVALID", diagnostic=True)
            return 2
    try:
        from wfdiag.gui.app import main as desktop

        return desktop(startup_check_root=root)
    except Exception:  # noqa: BLE001 -- last-resort, fixed message before/after Qt initialization.
        startup_error("GUI_STARTUP_FAILED", diagnostic=diagnostic)
        return 5


def emit_startup_check(checks: dict[str, bool]) -> None:
    if sys.stdout is not None:
        print(json.dumps(checks, sort_keys=True), flush=True)
