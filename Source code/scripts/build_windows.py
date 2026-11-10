"""Build a fresh local unsigned evaluation; never install, sign, publish or run collectors."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pefile
from prepare_notices import locked_packages, prepare, runtime_sbom

from wfdiag.collectors.process_runner import _bounded_process
from wfdiag.contracts.base import absolute_local_path
from wfdiag.services.cancellation import CancellationToken
from wfdiag.version import DISPLAY_VERSION, PUBLIC_VERSION, __version__

ROOT = Path(__file__).resolve().parents[1]
OPERATOR_DOCS = (
    "Documentation.docx",
    "Documentation.md",
    "installation.md",
    "troubleshooting.md",
    "privacy.md",
    "retention-upgrade-removal.md",
    "support-matrix.md",
    "known-limitations.md",
    "ai/setup.md",
    "ai/providers.md",
)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def build_environment() -> dict[str, str]:
    """Never resolve native dependencies from the host's unrelated tool PATH."""
    environment = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(("PYTHON", "QT_", "PYSIDE", "SHIBOKEN")) and k.upper() != "PATH"
    }
    windows = Path(os.environ["SystemRoot"])
    environment.update(
        PATH=os.pathsep.join(
            str(p)
            for p in (
                Path(sys.executable).parent,
                Path(sys.base_prefix),
                Path(sys.base_prefix) / "DLLs",
                windows / "System32",
                windows,
            )
        ),
        PYTHONIOENCODING="utf-8",
        PYTHONHASHSEED="0",
        PYINSTALLER_CONFIG_DIR=str(ROOT / ".build/cache/pyinstaller"),
    )
    return environment


def run(label: str, argv: list[str], logs: Path, *, timeout: int = 600) -> None:
    started = time.monotonic()
    environment = build_environment()
    result = _bounded_process(
        argv,
        cwd=ROOT,
        cancellation=CancellationToken(),
        timeout=timeout,
        output_limit=2 * 1024 * 1024,
        environment=environment,
    )
    (logs / (label + ".stdout.txt")).write_bytes(result.stdout)
    (logs / (label + ".stderr.txt")).write_bytes(result.stderr)
    save(
        logs / (label + ".json"),
        {
            "command_argv": argv,
            "cwd": str(ROOT),
            "at_utc": datetime.now(UTC).isoformat(),
            "seconds": time.monotonic() - started,
            "return_code": result.return_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "truncated": result.output_truncated,
            "read_failed": result.read_failed,
            "isolated_path": environment["PATH"].split(os.pathsep),
        },
    )
    print(
        json.dumps(
            {
                "step": label,
                "exit_code": result.return_code,
                "seconds": round(time.monotonic() - started, 3),
            }
        ),
        flush=True,
    )
    if (
        result.return_code
        or result.timed_out
        or result.cancelled
        or result.output_truncated
        or result.read_failed
    ):
        raise RuntimeError(f"Build step {label} failed; preserve its private logs")


def gui_smoke(executable: Path, root: Path, logs: Path, label: str) -> dict[str, object]:
    run(label, [str(executable), "--startup-check", str(root)], logs, timeout=30)
    checks = json.loads((logs / (label + ".stdout.txt")).read_text("utf-8"))
    expected = {
        "window_visible",
        "window_rendered",
        "icon_loaded",
        "synthetic_example_loaded",
        "ai_off",
        "history_off",
    }
    if (
        not isinstance(checks, dict)
        or set(checks) != expected
        or any(value is not True for value in checks.values())
    ):
        raise ValueError("Packaged GUI did not confirm all startup checks")
    if (root / ".application-instance.lock").exists():
        raise ValueError("Packaged GUI did not release its instance lock")
    return checks


def inspect_executable(path: Path, subsystem: int) -> dict[str, object]:
    with pefile.PE(str(path), fast_load=False) as image:
        if image.FILE_HEADER.Machine != 0x8664 or image.OPTIONAL_HEADER.Subsystem != subsystem:
            raise ValueError("Executable architecture/subsystem differs from the reviewed spec")
        manifests = []
        for entry in image.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == 24:
                for name in entry.directory.entries:
                    for language in name.directory.entries:
                        resource = language.data.struct
                        manifests.append(image.get_data(resource.OffsetToData, resource.Size))
        if not manifests or any(
            b"asInvoker" not in m or b"requireAdministrator" in m or b"highestAvailable" in m
            for m in manifests
        ):
            raise ValueError("Executable manifest is not asInvoker")
        security = image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if security.Size or security.VirtualAddress:
            raise ValueError(
                "Unexpected signature table; explicit signing verification is required"
            )
        return {
            "machine": "AMD64",
            "subsystem": subsystem,
            "execution_level": "asInvoker",
            "signing": "unsigned; certificate table absent",
            "bytes": path.stat().st_size,
            "sha256": sha(path),
        }


def member_parts(name: str) -> tuple[str, ...]:
    parts = PurePosixPath(name).parts
    if (
        not parts
        or PurePosixPath(name).is_absolute()
        or ".." in parts
        or "\\" in name
        or ":" in name
    ):
        raise ValueError("Unsafe archive member")
    # Pure validation of Windows aliases, reserved names, controls and streams.
    # No archive-selected drive/path is ever probed on the filesystem.
    absolute_local_path("C:/WFDiagArchive/" + name)
    return parts


def archive_guard(path: Path) -> None:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if any((m.external_attr >> 16) & 0o170000 == 0o120000 for m in members):
                raise ValueError("Unexpected wheel archive link")
            names = [m.filename for m in members]
    else:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if any(m.issym() or m.islnk() for m in members):
                raise ValueError("Unexpected source-archive link")
            names = [m.name for m in members]
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("Duplicate or case-colliding archive member")
    for name in names:
        parts = member_parts(name)
        if (
            PurePosixPath(name).is_absolute()
            or ".." in parts
            or any(
                p.casefold().startswith((".build", ".venv", ".env"))
                or p.casefold() in (".git", "release-local")
                for p in parts
            )
            or name.casefold().endswith((".evtx", ".pfx", ".p12", ".key"))
        ):
            raise ValueError("Private or unsafe archive member")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit-report",
        type=Path,
        required=True,
        help="Existing recorded CycloneDX audit below Product/.build",
    )
    args = parser.parse_args()
    audit_report = args.audit_report.resolve()
    if not audit_report.is_relative_to(ROOT / ".build") or not audit_report.is_file():
        raise ValueError("Use an existing local audit report under Product/.build")
    if (
        sys.platform != "win32"
        or sys.version_info[:2] != (3, 13)
        or struct.calcsize("P") != 8
        or Path(sys.executable).resolve() != (ROOT / ".venv/Scripts/python.exe").resolve()
    ):
        raise RuntimeError("Use the approved Product-local native Windows Python3.13 x64")
    if (
        tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]["version"]
        != __version__
    ):
        raise ValueError("Project and engine versions differ")
    pins = locked_packages(ROOT / "requirements-dev.txt")
    for name, version in pins.items():
        if importlib.metadata.version(name) != version:
            raise ValueError(f"Installed {name} differs from the exact development lock")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    local = ROOT / "release-local" / ("evaluation-" + stamp)
    local.mkdir(parents=True)
    work = ROOT / ".build" / ("package-" + stamp)
    work.mkdir()
    logs = work / "logs"
    logs.mkdir()
    notices = work / "notices"
    prepare(notices)
    runtime_sbom(audit_report, work / "runtime-packages.cdx.json")
    python = str(Path(sys.executable).resolve())
    run("collector-syntax", [python, str(ROOT / "scripts/parse_collectors.py")], logs, timeout=40)
    run("icon", [python, str(ROOT / "scripts/generate_app_icon.py")], logs, timeout=30)
    git = ["git", "-c", f"safe.directory={ROOT.as_posix()}"]
    revision = subprocess.check_output([*git, "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    status = subprocess.check_output([*git, "status", "--porcelain"], cwd=ROOT, text=True)
    names = (
        subprocess.check_output(
            [*git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    fingerprints = {n: sha(ROOT / n) for n in sorted(set(names)) if n and (ROOT / n).is_file()}
    save(
        work / "source.json",
        {
            "source_commit": revision,
            "git_status": status,
            "source_files": fingerprints,
            "platform": platform.platform(),
            "python": sys.version,
            "locks": {
                n: sha(ROOT / n)
                for n in ("requirements.txt", "requirements-desktop-ai.txt", "requirements-dev.txt")
            },
        },
    )
    run(
        "wheel-sdist", [python, "-I", "-m", "build", "--no-isolation", "--outdir", str(local)], logs
    )
    for artifact in local.iterdir():
        if artifact.suffix == ".whl" or artifact.name.endswith(".tar.gz"):
            archive_guard(artifact)
    run(
        "portable",
        [
            python,
            "-I",
            "-m",
            "PyInstaller",
            "--distpath",
            str(local),
            "--workpath",
            str(work / "freeze"),
            str(ROOT / "packaging/firewall-assistant-windows.spec"),
        ],
        logs,
    )
    portable = local / "FirewallAssistant"
    desktop_checks = gui_smoke(
        portable / "FirewallAssistant.exe", work / "gui-startup-private", logs, "desktop-startup"
    )
    binaries = {
        name: inspect_executable(portable / name, mode)
        for name, mode in (("FirewallAssistant.exe", 2), ("wfdiag.exe", 3))
    }
    shutil.copytree(notices, portable / "notices")
    shutil.copyfile(work / "runtime-packages.cdx.json", portable / "runtime-packages.cdx.json")
    shutil.copytree(ROOT / "examples", portable / "examples")
    for name in OPERATOR_DOCS:
        destination = portable / "docs" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "docs" / name, destination)
    (portable / "READ-ME.txt").write_text(
        f"Windows Firewall Troubleshooting Assistant {DISPLAY_VERSION} — unsigned evaluation\n"
        f"Internal package metadata: {__version__}\n\n"
        "Extract the whole folder and keep both executables and _internal together.\n"
        "FirewallAssistant.exe is the desktop launcher; wfdiag.exe is the administrator CLI.\n"
        "AI starts off; no API key/internet is needed for diagnostics or the synthetic example.\n"
        "Never disable security controls or bypass script policy to run this evaluation.\n"
        "No firewall rule/audit setting is changed by the product. Open example is synthetic.\n\n"
        "Read docs/Documentation.docx for operating steps.\n"
        "This unsigned release candidate awaits owner human review and a stable release decision.\n"
        "Exact completed checks and remaining limitations are recorded alongside the package.\n"
        "Broad native/accessibility/compatibility certification and signing remain unverified.\n"
        "See docs/installation.md, docs/known-limitations.md and docs/ai/setup.md.\n"
        "See NOTICES under notices; public redistribution/licensing review remains pending.\n",
        encoding="utf-8",
        newline="\n",
    )
    run("console-help", [str(portable / "wfdiag.exe"), "--help"], logs, timeout=30)
    run("console-version", [str(portable / "wfdiag.exe"), "--version"], logs, timeout=30)
    run(
        "synthetic-share",
        [
            str(portable / "wfdiag.exe"),
            "report",
            "--analysis",
            str(portable / "examples/expected-analysis.json"),
            "--mode",
            "share",
            "--out",
            str(work / "frozen-synthetic-share.html"),
        ],
        logs,
        timeout=45,
    )
    inventory = {}
    for path in sorted(portable.rglob("*")):
        if path.is_symlink():
            raise ValueError("Unexpected portable filesystem redirection")
        if path.is_file():
            name = path.relative_to(portable).as_posix()
            if any(p in (".build", ".venv", ".git", "lab", "tests") for p in Path(name).parts):
                raise ValueError("Unexpected private/lab/test file in portable distribution")
            inventory[name] = {"bytes": path.stat().st_size, "sha256": sha(path)}
    manifest = {
        "schema_version": 1,
        "status": "unsigned local release candidate; owner human review pending",
        "version": __version__,
        "local_packaged_gui_startup": desktop_checks,
        "source_commit": revision,
        "source_fingerprint": sha(work / "source.json"),
        "executables": binaries,
        "files": inventory,
        "release_gates_passed": [],
        "native_clean_vm_gui_live_acceptance": "blocked",
        "redistribution_review": "blocked; owner licensing/source/notices decisions pending",
    }
    save(portable / "build-manifest.json", manifest)
    save(local / "build-manifest.json", manifest)
    archive_path = local / f"FirewallAssistant-{PUBLIC_VERSION}-RC1-windows-x64.zip"
    with zipfile.ZipFile(
        archive_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as archive:
        for path in sorted(portable.rglob("*")):
            if path.is_file():
                archive.write(path, Path("FirewallAssistant") / path.relative_to(portable))
    with (local / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as sums:
        for path in sorted(local.iterdir()):
            if path.is_file() and path.name != "SHA256SUMS":
                sums.write(f"{sha(path)}  {path.name}\n")
    save(
        work / "result.json",
        {
            "local_candidate": str(local),
            "archive": str(archive_path),
            "sha256": sha(archive_path),
            "executables": binaries,
            "release_gates_passed": [],
            "status": "unsigned evaluation; local smoke only; native/GUI/live/release acceptance blocked",
        },
    )
    print(
        json.dumps(
            {
                "candidate": str(local),
                "archive_sha256": sha(archive_path),
                "portable_files": len(inventory),
                "status": "unsigned evaluation",
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
