"""Own synthetic program bytes only; no GUI launch, native permissions or trust claim."""

import hashlib
import json
from pathlib import Path

import pytest

from wfdiag.gui.installation import verify_program_root
from wfdiag.version import __version__


def invented(root: Path):
    content = b"invented program bytes, never executed"
    (root / "wfdiag.exe").write_bytes(content)
    manifest = {
        "version": __version__,
        "files": {
            "wfdiag.exe": {
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        },
    }
    (root / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_matching_program_consistency_does_not_execute_it(tmp_path):
    invented(tmp_path)
    verify_program_root(tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        "version",
        "hash",
        "size",
        "missing_engine",
        "missing_manifest",
        "boolean_size",
        "oversize",
        "missing_identity",
    ],
)
def test_missing_mismatched_or_modified_engine_is_refused(tmp_path, change):
    manifest = invented(tmp_path)
    if change == "version":
        manifest["version"] = "0.0.0"
    elif change == "hash":
        manifest["files"]["wfdiag.exe"]["sha256"] = "0" * 64
    elif change == "size":
        (tmp_path / "wfdiag.exe").write_bytes(b"changed")
    elif change == "boolean_size":
        manifest["files"]["wfdiag.exe"]["bytes"] = True
    elif change == "oversize":
        manifest["files"]["wfdiag.exe"]["bytes"] = 64 * 1024 * 1024 + 1
    elif change == "missing_identity":
        manifest["files"] = {}
    if change == "missing_engine":
        (tmp_path / "wfdiag.exe").unlink()
    if change != "missing_manifest":
        (tmp_path / "build-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    else:
        (tmp_path / "build-manifest.json").unlink()
    with pytest.raises((OSError, ValueError)):
        verify_program_root(tmp_path)


def test_duplicate_manifest_identity_is_refused(tmp_path):
    invented(tmp_path)
    (tmp_path / "build-manifest.json").write_text(
        '{"version":"1.0.0rc1","version":"1.0.0rc1","files":{}}', encoding="utf-8"
    )
    with pytest.raises(ValueError):
        verify_program_root(tmp_path)
