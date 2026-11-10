# Local unsigned evaluation build. Reviewed PyInstaller6.22.3, Python3.13 x64.
# Two analyses keep Qt runtime hooks out of the console entry; shared COLLECT
# deduplicates common runtime libraries in one complete portable directory.
from pathlib import Path
import os
import site
import sys

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo,
    VarStruct, VSVersionInfo,
)

root = Path(SPECPATH).parent
if Path(sys.prefix).resolve() != (root / ".venv").resolve():
    raise RuntimeError("Use the approved local build environment")
# PyInstaller6.22.3's binary-layout helper probes the user site even under -I.
# Scope only this process's cached site value to the already-approved venv.
# Do not inspect/change the inaccessible roaming user package directory or ACL.
site.USER_SITE = str(root / ".venv/Lib/site-packages")
resources = root / "src/wfdiag/resources"
gui_resources = root / "src/wfdiag/gui/resources"
icon = str(gui_resources / "app.ico")
manifest = str(root / "packaging/as-invoker.manifest")


def version_info(filename):
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=(1, 0, 0, 0), prodvers=(1, 0, 0, 0),
                         mask=0x3f, flags=0x2, OS=0x40004, fileType=0x1,
                         subtype=0x0, date=(0, 0)),
        kids=[StringFileInfo([StringTable("040904B0", [
            StringStruct("FileDescription", "Windows Firewall Troubleshooting Assistant — release candidate"),
            StringStruct("FileVersion", "1.0.0.0"),
            StringStruct("InternalName", Path(filename).stem),
            StringStruct("OriginalFilename", filename),
            StringStruct("ProductName", "Windows Firewall Troubleshooting Assistant"),
            StringStruct("ProductVersion", "1.0.0rc1"),
            StringStruct("Comments", "Unsigned release candidate; awaiting owner human review"),
        ])]), VarFileInfo([VarStruct("Translation", [1033, 1200])])],
    )


console = Analysis(
    [str(root / "packaging/cli_entry.py")], pathex=[str(root / "src")],
    datas=[(str(resources), "wfdiag/resources")], binaries=[], hiddenimports=[],
    excludes=["PySide6", "PyQt5", "PyQt6", "PySide2", "tkinter", "wfdiag.gui", "wfdiag.ai"],
    noarchive=False,
)
desktop = Analysis(
    [str(root / "packaging/gui_entry.py")], pathex=[str(root / "src")],
    datas=[(str(resources), "wfdiag/resources"),
           (str(gui_resources), "wfdiag/gui/resources")], binaries=[],
    hiddenimports=["wfdiag.ai.context", "wfdiag.ai.credentials", "wfdiag.ai.models",
                   "wfdiag.ai.policy", "wfdiag.ai.service", "wfdiag.ai.transport",
                   "wfdiag.ai.usage", "wfdiag.ai.providers.openai",
                   "wfdiag.ai.providers.anthropic", "wfdiag.ai.providers.gemini",
                   "httpx", "certifi"],
    excludes=["PyQt5", "PyQt6", "PySide2", "tkinter", "PySide6.QtWebEngineCore",
              "PySide6.QtWebEngineWidgets", "PySide6.QtQml", "PySide6.QtQuick"],
    noarchive=False,
)
# Reject ambient toolchain DLLs even if a future hook adds another search path.
# Windows owns ICU/API-set DLLs; never substitute a Poppler/other-tool build.
allowed_binary_roots = [Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(),
                        (Path(os.environ["SystemRoot"]) / "System32").resolve()]
for analysis in (console, desktop):
    for destination, source, kind in analysis.binaries:
        if not any(Path(source).resolve().is_relative_to(base) for base in allowed_binary_roots):
            raise RuntimeError("A binary resolved outside the approved Python/Windows roots")
        if Path(destination).name.lower() in {"icuuc.dll", "icuin.dll", "icu.dll"}:
            raise RuntimeError("Windows ICU must resolve from Windows, not the portable folder")
cli_pyz = PYZ(console.pure)
gui_pyz = PYZ(desktop.pure)
cli = EXE(cli_pyz, console.scripts, [], exclude_binaries=True, name="wfdiag",
          console=True, debug=False, upx=False, strip=False, icon=icon,
          manifest=manifest, version=version_info("wfdiag.exe"),
          uac_admin=False, uac_uiaccess=False)
gui = EXE(gui_pyz, desktop.scripts, [], exclude_binaries=True, name="FirewallAssistant",
          console=False, debug=False, upx=False, strip=False, icon=icon,
          manifest=manifest, version=version_info("FirewallAssistant.exe"),
          uac_admin=False, uac_uiaccess=False, disable_windowed_traceback=True)
bundle = COLLECT(gui, cli, desktop.binaries, desktop.datas, console.binaries, console.datas,
                 name="FirewallAssistant", upx=False, strip=False)
