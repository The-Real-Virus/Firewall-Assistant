"""Check a real evaluation, including isolated native GUI startup; no collectors."""

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from build_windows import (
    OPERATOR_DOCS,
    ROOT,
    archive_guard,
    gui_smoke,
    inspect_executable,
    member_parts,
    run,
    save,
    sha,
)
from PyInstaller.archive.readers import CArchiveReader

from wfdiag.gui.installation import verify_program_root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    args = parser.parse_args()
    candidate = args.candidate.resolve()
    if not candidate.is_relative_to(ROOT / "release-local"):
        raise ValueError("Select a local evaluation under Product/release-local")
    portable = candidate / "FirewallAssistant"
    manifest = json.loads((portable / "build-manifest.json").read_text("utf-8"))
    files = manifest["files"]
    actual = {p.relative_to(portable).as_posix() for p in portable.rglob("*") if p.is_file()}
    if actual != {*files, "build-manifest.json"}:
        raise ValueError("Portable inventory differs from its recorded file set")
    for name, expected in files.items():
        member_parts(name)
        path = portable / name
        if (
            path.is_symlink()
            or path.stat().st_size != expected["bytes"]
            or sha(path) != expected["sha256"]
        ):
            raise ValueError("Portable file fingerprint mismatch")
    cli_info = inspect_executable(portable / "wfdiag.exe", 3)
    gui_info = inspect_executable(portable / "FirewallAssistant.exe", 2)
    verify_program_root(portable)  # Read-only engine consistency; no GUI/startup/private storage.
    for name in OPERATOR_DOCS:
        if sha(portable / "docs" / name) != sha(ROOT / "docs" / name):
            raise ValueError("Packaged operator instructions differ from reviewed source")
    if (
        cli_info != manifest["executables"]["wfdiag.exe"]
        or gui_info != manifest["executables"]["FirewallAssistant.exe"]
    ):
        raise ValueError("Executable identity mismatch")
    archive = CArchiveReader(str(portable / "wfdiag.exe"))
    pyz = archive.open_embedded_archive("PYZ.pyz")
    if any(n.startswith(("PySide6", "httpx", "wfdiag.ai", "wfdiag.gui")) for n in pyz.toc):
        raise ValueError("Console executable unexpectedly requires optional GUI/AI modules")
    wheel = next(candidate.glob("*.whl"))
    archive_guard(wheel)
    with zipfile.ZipFile(wheel) as source:
        wheel_names = set(source.namelist())
        for name in wheel_names:
            if name.startswith("wfdiag/") and not name.endswith("/"):
                path = ROOT / "src" / name
                if not path.is_file() or hashlib.sha256(source.read(name)).hexdigest() != sha(path):
                    raise ValueError("Wheel source/resource content differs from current source")
    required = {
        "wfdiag/gui/resources/app.ico",
        "wfdiag/gui/resources/synthetic-analysis.json",
        "wfdiag/resources/notices.txt",
        "wfdiag/resources/ai/providers-v1.json",
        "wfdiag/resources/ai/assistant-v2-models.json",
        "wfdiag/resources/powershell/Collect-Events.ps1",
    }
    if not required <= wheel_names:
        raise ValueError("Wheel is missing required integrated resources")
    for source in candidate.glob("*.tar.gz"):
        archive_guard(source)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    work = ROOT / ".build" / ("artifact-check-" + stamp)
    work.mkdir()
    logs = work / "logs"
    logs.mkdir()
    location = work / "Package path with spaces Ω"
    location.mkdir()
    zip_path = next(candidate.glob("FirewallAssistant-*.zip"))
    with zipfile.ZipFile(zip_path) as zipped:
        entries = zipped.infolist()
        names = [entry.filename for entry in entries]
        if len({n.casefold() for n in names}) != len(names):
            raise ValueError("Duplicate or case-colliding ZIP entries")
        for entry in entries:
            parts = member_parts(entry.filename)
            if (
                not parts
                or parts[0] != "FirewallAssistant"
                or ".." in parts
                or PurePosixPath(entry.filename).is_absolute()
                or stat.S_ISLNK(entry.external_attr >> 16)
            ):
                raise ValueError("Unsafe portable ZIP member")
            relative = PurePosixPath(*parts[1:]).as_posix()
            original = portable / relative
            if not original.is_file() or entry.file_size != original.stat().st_size:
                raise ValueError("ZIP contents differ from the reviewed portable folder")
            target = location.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            count = 0
            digest = hashlib.sha256()
            with zipped.open(entry) as input_stream, target.open("xb") as output:
                while chunk := input_stream.read(65536):
                    count += len(chunk)
                    if count > entry.file_size:
                        raise ValueError("Actual ZIP bytes exceed the recorded artifact size")
                    digest.update(chunk)
                    output.write(chunk)
            if count != entry.file_size or digest.hexdigest() != sha(original):
                raise ValueError("ZIP payload fingerprint differs")
        if set(names) != {"FirewallAssistant/" + n for n in actual}:
            raise ValueError("ZIP inventory is incomplete")
    extracted = location / "FirewallAssistant"
    desktop_checks = gui_smoke(
        extracted / "FirewallAssistant.exe",
        work / "gui-startup-private",
        logs,
        "unicode-gui-startup",
    )
    run("unicode-help", [str(extracted / "wfdiag.exe"), "--help"], logs, timeout=30)
    run("unicode-version", [str(extracted / "wfdiag.exe"), "--version"], logs, timeout=30)
    output = work / "synthetic-share.html"
    run(
        "unicode-share",
        [
            str(extracted / "wfdiag.exe"),
            "report",
            "--analysis",
            str(extracted / "examples/expected-analysis.json"),
            "--mode",
            "share",
            "--out",
            str(output),
        ],
        logs,
        timeout=45,
    )
    text = output.read_text("utf-8")
    if (
        "DEFAULT_BLOCK" not in text
        or re.search(r"<(script|iframe|object)\b", text, re.IGNORECASE)
        or "C:\\Training" in text
    ):
        raise ValueError("Unexpected synthetic share report")
    # Use the existing independently hash-verified lock environment for an actual
    # wheel reinstall. No index/dependency resolution or source editable install.
    target_python = ROOT / ".venv-lockcheck/Scripts/python.exe"
    run(
        "wheel-install",
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-m",
            "pip",
            "--python",
            str(target_python),
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            str(wheel),
        ],
        logs,
        timeout=90,
    )
    probe = r"""
import builtins, socket, sys
from pathlib import Path
old=builtins.__import__
def guarded(name,*args,**kwargs):
    if name.startswith(('PySide6','httpx','wfdiag.ai','wfdiag.gui')):
        raise AssertionError('Optional import in installed CLI: '+name)
    return old(name,*args,**kwargs)
def no_network(*args,**kwargs):raise AssertionError('Network in installed core')
builtins.__import__=guarded
socket.socket.connect=no_network;socket.getaddrinfo=no_network
import wfdiag
assert 'site-packages' in Path(wfdiag.__file__).parts and 'src' not in Path(wfdiag.__file__).parts
from importlib.resources import files
assert len(list(files('wfdiag').joinpath('resources/schemas').iterdir()))==22
assert files('wfdiag').joinpath('gui/resources/app.ico').read_bytes()[:4]==b'\x00\x00\x01\x00'
from wfdiag.cli import main
try:main(['--help'])
except SystemExit as e:assert e.code==0
"""
    run("installed-wheel-probe", [str(target_python), "-I", "-c", probe], logs, timeout=30)
    result = {
        "candidate": str(candidate),
        "zip_sha256": sha(zip_path),
        "files_verified": len(files),
        "cli": cli_info,
        "gui": gui_info,
        "wheel_resource_bytes_match_source": True,
        "console_optional_modules_absent": True,
        "engine_manifest_consistency": True,
        "operator_instructions_match_source": True,
        "unicode_safe_cli_smoke": "pass",
        "installed_wheel_core_probe": "pass",
        "actual_gui_startup": "pass; current development host, isolated private root",
        "actual_gui_startup_checks": desktop_checks,
        "windows10_vm_gui_retest": "blocked; replacement not tested by owner yet",
        "native_collection_privacy_clean_vm_live_release": "blocked",
        "release_gates_passed": [],
    }
    save(work / "result.json", result)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
