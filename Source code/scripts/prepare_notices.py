"""Prepare local dependency inventory and notices; never grants redistribution approval."""

import importlib.metadata
import json
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def locked_packages(path: Path) -> dict[str, str]:
    packages = {}
    for line in path.read_text("utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", line)
        if match:
            name = re.sub(r"[-_.]+", "-", match[1]).lower()
            packages[name] = match[2]
    if not packages:
        raise ValueError("The exact package lock is missing or empty")
    return packages


def prepare(destination: Path) -> dict[str, object]:
    destination.mkdir()  # No overwrite of prior evidence or notices.
    pins = locked_packages(ROOT / "requirements-desktop-ai.txt")
    inventory = []
    summaries = []
    for name, version in {**pins, "pyinstaller": importlib.metadata.version("pyinstaller")}.items():
        distribution = importlib.metadata.distribution(name)
        if distribution.version != version:
            raise ValueError("Installed dependency differs from the exact lock")
        license_text = (
            distribution.metadata.get("License-Expression")
            or distribution.metadata.get("License")
            or "Unspecified; review included texts"
        )
        package_dir = destination / name
        package_dir.mkdir()
        copied = []
        for entry in distribution.files or ():
            # License records declared by the installed distribution only. Do not copy
            # arbitrary source files, case paths, settings, credentials or logs.
            if "license" not in str(entry).lower() and "copying" not in str(entry).lower():
                continue
            source = Path(distribution.locate_file(entry))
            if source.is_file():
                target = package_dir / f"{len(copied) + 1}-{source.name}"
                shutil.copyfile(source, target)
                copied.append(target.relative_to(destination).as_posix())
        if not copied:
            raise ValueError(f"No installed license text found for {name}")
        inventory.append(
            {
                "name": name,
                "version": version,
                "declared_license": license_text,
                "license_files": copied,
                "scope": "runtime package" if name in pins else "freezer bootloader/build tool",
            }
        )
        summaries.append(f"{name} {version}: {license_text}")
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_license.is_file():
        raise ValueError("The actual bundled Python license is unavailable")
    shutil.copyfile(python_license, destination / "Python-LICENSE.txt")
    notes = (
        """Third party dependency notices

Unsigned development evaluation. Distribution approval and native component review are pending.
Bundled dependencies retain their own license terms and notices.
The full installed dependency license texts accompany this index in the notices directory.
Python runtime terms are in notices/Python-LICENSE.txt. PyInstaller bootloader/build-tool terms
are separate. The native library/file inventory must be matched to the final portable build.

PySide6/Shiboken metadata lists LGPL/GPL alternatives. Their wheel includes a commercial notice
as well. No commercial license is claimed. The owner must select the distribution route and
complete applicable corresponding-source, native third-party notice and replacement obligations
before public redistribution. Dynamic Qt libraries must remain replaceable in the one-folder
package; replacement/source/rebuild instructions and verified matching sources are still needed.

Official licensing: https://doc.qt.io/qt-6.12/licensing.html
Qt for Python: https://doc.qt.io/qtforpython-6/licenses.html
No API key, cloud request, firewall control or telemetry is needed to read these notices.

Locked package inventory
"""
        + "\n".join(summaries)
        + "\n"
    )
    (destination / "NOTICES.txt").write_text(notes, encoding="utf-8", newline="\n")
    report = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "packages": inventory,
        "redistribution_review": "blocked; owner Qt license choice/native notices/source/replacement review pending",
    }
    (destination / "inventory.json").write_text(json.dumps(report, indent=2) + "\n", "utf-8")
    (ROOT / "src/wfdiag/resources/notices.txt").write_text(notes, encoding="utf-8", newline="\n")
    return report


def runtime_sbom(audit_path: Path, destination: Path) -> None:
    """Filter the actual successful67-package audit inventory to the locked16 runtime packages."""
    original = json.loads(audit_path.read_text("utf-8"))
    development = locked_packages(ROOT / "requirements-dev.txt")
    all_components = original.get("components", [])
    normalized = {re.sub(r"[-_.]+", "-", c["name"]).lower(): c["version"] for c in all_components}
    if (
        original.get("bomFormat") != "CycloneDX"
        or original.get("specVersion") != "1.4"
        or len(all_components) != len(development)
        or normalized != development
        or original.get("vulnerabilities")
    ):
        raise ValueError("Audit must contain the exact full development lock and no known findings")
    # Inventory alone does not establish an actual audit command outcome. The caller must
    # retain its successful --strict audit log; runtime filtering must not discard findings.
    pins = locked_packages(ROOT / "requirements-desktop-ai.txt")
    components = [
        c for c in original["components"] if re.sub(r"[-_.]+", "-", c["name"]).lower() in pins
    ]
    if len(components) != len(pins) or any(
        c["version"] != pins[re.sub(r"[-_.]+", "-", c["name"]).lower()] for c in components
    ):
        raise ValueError("Audit inventory is not the exact locked runtime subset")
    refs = {c["bom-ref"] for c in components}
    dependencies = [
        {"ref": d["ref"], "dependsOn": [r for r in d.get("dependsOn", []) if r in refs]}
        for d in original.get("dependencies", [])
        if d["ref"] in refs
    ]
    result = {
        **original,
        "serialNumber": "urn:uuid:" + str(uuid4()),
        "components": components,
        "dependencies": dependencies,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "properties": [
                {
                    "name": "wfdiag:inventory-scope",
                    "value": "Runtime Python package subset of recorded successful dev-lock PyPI audit; native/freezer inventory separate",
                }
            ],
        },
    }
    with destination.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
