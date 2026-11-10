"""Build the isolated lab-only TCP fixture; never starts a socket or changes policy."""

import importlib.metadata
import json
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

from build_windows import ROOT, inspect_executable, run, save, sha
from prepare_notices import locked_packages


def main() -> None:
    if (
        sys.platform != "win32"
        or sys.version_info[:2] != (3, 13)
        or struct.calcsize("P") != 8
        or Path(sys.executable).resolve() != (ROOT / ".venv/Scripts/python.exe").resolve()
    ):
        raise RuntimeError("Use the approved local Windows3.13x64 development environment")
    for name, version in locked_packages(ROOT / "requirements-dev.txt").items():
        if importlib.metadata.version(name) != version:
            raise ValueError("Fixture build dependencies differ from the exact approved lock")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    work = ROOT / ".build" / ("lab-fixture-" + stamp)
    work.mkdir()
    logs = work / "logs"
    logs.mkdir()
    source = ROOT / "scripts/lab/tcp_fixture.py"
    manifest = ROOT / "packaging/as-invoker.manifest"
    # Same reviewed build-process-only site isolation as ADR0016. No installed tool edits.
    spec = work / "fixture.spec"
    spec.write_text(
        "import site, sys\nfrom pathlib import Path\n"
        f"root=Path({str(ROOT)!r})\n"
        "assert Path(sys.prefix).resolve()==(root/'.venv').resolve()\n"
        "site.USER_SITE=str(root/'.venv/Lib/site-packages')\n"
        f"a=Analysis([{str(source)!r}],pathex=[],binaries=[],datas=[],hiddenimports=[],"
        "excludes=['wfdiag','PySide6','httpx','tkinter'],noarchive=False)\n"
        "pyz=PYZ(a.pure)\n"
        "exe=EXE(pyz,a.scripts,[],exclude_binaries=True,name='WFDiagLabFixture',"
        f"console=True,debug=False,upx=False,strip=False,manifest={str(manifest)!r})\n"
        "coll=COLLECT(exe,a.binaries,a.datas,strip=False,upx=False,name='WFDiagLabFixture')\n",
        encoding="utf-8",
        newline="\n",
    )
    run(
        "freeze-lab-fixture",
        [
            sys.executable,
            "-I",
            "-m",
            "PyInstaller",
            "--distpath",
            str(work / "dist"),
            "--workpath",
            str(work / "freeze"),
            str(spec),
        ],
        logs,
    )
    executable = work / "dist/WFDiagLabFixture/WFDiagLabFixture.exe"
    binary = inspect_executable(executable, 3)
    # --help exits before address parsing/socket creation; do not execute a lab exchange here.
    run("fixture-help-only", [str(executable), "--help"], logs, timeout=30)
    result = {
        "status": "lab-only unsigned fixture build; native network/policy validation blocked",
        "executable": str(executable),
        "binary": binary,
        "source_sha256": sha(source),
        "manifest_sha256": sha(manifest),
        "policy_changes": False,
        "sockets_started": False,
        "a01_approved": False,
    }
    save(work / "result.json", result)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
