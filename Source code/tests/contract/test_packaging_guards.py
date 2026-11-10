"""Development artifact guards; these tests do not certify a portable executable."""

import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parents[2] / "scripts"


@pytest.fixture
def build_helpers(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(
        "wfdiag_build_helpers_test", SCRIPTS / "build_windows.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "name",
    [
        ".build/state.json",
        "source/.venv/private.txt",
        "source/.env",
        "../outside.py",
        "/absolute.py",
        "source/key.pfx",
        "C:/outside.py",
        "source/..\\outside.py",
        "source/data.json:stream",
        "source/CON.txt",
        "source/trailing.txt.",
        "source/.BUILD/private.json",
        "source/private.KEY",
    ],
)
def test_wheel_private_and_unsafe_names_are_rejected(build_helpers, tmp_path: Path, name: str):
    path = tmp_path / "synthetic.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, "synthetic")
    with pytest.raises(ValueError):
        build_helpers.archive_guard(path)


def test_normal_package_member_allowed(build_helpers, tmp_path: Path):
    path = tmp_path / "synthetic.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("wfdiag/resources/ai/system-v1.txt", "synthetic")
    build_helpers.archive_guard(path)


def test_source_archive_link_rejected(build_helpers, tmp_path: Path):
    path = tmp_path / "synthetic.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        item = tarfile.TarInfo("source/link")
        item.type = tarfile.SYMTYPE
        item.linkname = "../outside"
        archive.addfile(item, io.BytesIO())
    with pytest.raises(ValueError, match="link"):
        build_helpers.archive_guard(path)


def test_existing_notices_are_never_overwritten(build_helpers, tmp_path: Path):
    destination = tmp_path / "existing"
    destination.mkdir()
    original = destination / "keep.txt"
    original.write_text("owner original", encoding="utf-8")
    with pytest.raises(FileExistsError):
        build_helpers.prepare(destination)
    assert original.read_text("utf-8") == "owner original"
    assert list(destination.iterdir()) == [original]


def test_native_dependency_path_excludes_ambient_tools(build_helpers, monkeypatch):
    import os
    import sys

    monkeypatch.setenv("PATH", "C:/UNRELATED-TOOL-ICU;C:/UNRELATED-GIT")
    monkeypatch.setenv("QT_PLUGIN_PATH", "C:/UNRELATED-QT")
    monkeypatch.setenv("PYTHONPATH", "C:/UNRELATED-PYTHON")
    monkeypatch.setenv("SystemRoot", "C:/Windows")
    environment = build_helpers.build_environment()
    assert "UNRELATED" not in environment["PATH"]
    assert "QT_PLUGIN_PATH" not in environment and "PYTHONPATH" not in environment
    assert str(Path(sys.executable).parent) in environment["PATH"].split(os.pathsep)
    assert str(Path("C:/Windows/System32")) in environment["PATH"].split(os.pathsep)


def test_wheel_symlink_rejected(build_helpers, tmp_path: Path):
    path = tmp_path / "synthetic.whl"
    with zipfile.ZipFile(path, "w") as archive:
        entry = zipfile.ZipInfo("wfdiag/link")
        entry.external_attr = 0o120777 << 16
        archive.writestr(entry, "../outside")
    with pytest.raises(ValueError, match="link"):
        build_helpers.archive_guard(path)


@pytest.mark.parametrize("problem", ["empty", "missing", "duplicate", "stale", "vulnerability"])
def test_invalid_or_vulnerable_audit_cannot_be_filtered_away(build_helpers, tmp_path, problem):
    from prepare_notices import locked_packages, runtime_sbom

    pins = locked_packages(build_helpers.ROOT / "requirements-dev.txt")
    components = [{"name": n, "version": v, "bom-ref": n} for n, v in pins.items()]
    record = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": components}
    if problem == "empty":
        record["components"] = []
    elif problem == "missing":
        components.pop()
    elif problem == "duplicate":
        components[-1] = components[0]
    elif problem == "stale":
        components[0]["version"] = "0.0.0"
    else:
        record["vulnerabilities"] = [{"id": "synthetic advisory must not be dropped"}]
    source = tmp_path / "invented-audit.json"
    source.write_text(json.dumps(record), encoding="utf-8")
    destination = tmp_path / "should-not-exist.json"
    with pytest.raises(ValueError, match="exact full development"):
        runtime_sbom(source, destination)
    assert not destination.exists()
