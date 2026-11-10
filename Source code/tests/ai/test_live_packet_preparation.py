"""Offline review artifacts confer no live authority and never construct a credential/client."""

import copy
import hashlib
import json
import runpy
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
NAMESPACE = runpy.run_path(str(ROOT / "scripts/prepare_ai_live_packet.py"))
CATALOG = (ROOT / "tests/fixtures/ai/evaluation-v1.json").read_bytes()


def test_exact_proposed_attempts_hashes_and_blocked_authority() -> None:
    files = NAMESPACE["packet_files"](CATALOG)
    manifest = json.loads(files["manifest.json"])
    assert manifest["approval_status"] == "not_approved" and manifest["approval_ready"] is False
    assert manifest["maximum_approved_spend_usd"] is None
    assert manifest["owner_paid_testing_limit_usd"] == 0
    assert manifest["input_token_allowance"] is None
    assert manifest["proposed_attempts"] == 39 and len(files) == 40
    assert Counter(row["provider"] for row in manifest["requests"]) == {
        "openai": 13,
        "anthropic": 13,
        "google": 13,
    }
    for row in manifest["requests"]:
        body = files[row["file"]]
        assert hashlib.sha256(body).hexdigest() == row["sha256"] and len(body) == row["bytes"]
        assert row["max_output_tokens"] == 1024 and row["attempts"] == 1
        assert row["live_validation"] == row["human_review"] == "blocked"
        value = json.loads(body)
        output_name = {"openai": "max_output_tokens", "anthropic": "max_tokens"}.get(
            row["provider"]
        )
        assert (
            value[output_name] if output_name else value["generationConfig"]["maxOutputTokens"]
        ) == 1024
    assert files == NAMESPACE["packet_files"](CATALOG)


@pytest.mark.parametrize(
    "mutation", ["not_synthetic", "subset_change", "missing_scene", "duplicate_scene"]
)
def test_catalog_scope_changes_refuse_preparation(mutation: str) -> None:
    raw = copy.deepcopy(json.loads(CATALOG))
    if mutation == "not_synthetic":
        raw["synthetic_only"] = False
    elif mutation == "subset_change":
        raw["live_candidate_subset"].pop()
    elif mutation == "missing_scene":
        raw["cases"] = [case for case in raw["cases"] if case["id"] != "explicit-block"]
    else:
        raw["cases"].append(raw["cases"][0])
    with pytest.raises(ValueError):
        NAMESPACE["packet_files"](json.dumps(raw).encode())


def test_existing_packet_never_overwritten_and_tampering_refused(tmp_path: Path) -> None:
    files = NAMESPACE["packet_files"](CATALOG)
    path = tmp_path / "packet"
    NAMESPACE["write_packet"](path, files)
    NAMESPACE["check_packet"](path, files)
    with pytest.raises(FileExistsError):
        NAMESPACE["write_packet"](path, files)
    target = path / next(name for name in files if name != "manifest.json")
    original = target.read_bytes()
    target.write_bytes(original + b" ")
    with pytest.raises(ValueError, match="bytes"):
        NAMESPACE["check_packet"](path, files)
    target.write_bytes(original)
    (path / ".incomplete").write_text("unfinished", encoding="utf-8")
    with pytest.raises(ValueError, match="file set"):
        NAMESPACE["check_packet"](path, files)


def test_preparation_needs_no_network_httpx_or_credential_construction() -> None:
    program = r"""
import builtins, json, runpy, socket, sys
from pathlib import Path
def forbidden(*args, **kwargs):
    raise AssertionError("Offline packet preparation attempted a network or credential action")
socket.getaddrinfo = forbidden
socket.socket.connect = forbidden
original_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(("httpx", "wfdiag.ai.transport", "wfdiag.ai.windows_credentials")):
        return forbidden()
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded
from wfdiag.ai.credentials import KeyMaterial, SessionKeys, WindowsCredentialStore
KeyMaterial.__init__ = forbidden
SessionKeys.__init__ = forbidden
WindowsCredentialStore.__init__ = forbidden
root = Path.cwd()
namespace = runpy.run_path(str(root / "scripts/prepare_ai_live_packet.py"))
files = namespace["packet_files"]((root / "tests/fixtures/ai/evaluation-v1.json").read_bytes())
assert len(files) == 40 and "httpx" not in sys.modules and "wfdiag.ai.transport" not in sys.modules
print("39 synthetic request files; zero sends/keys/clients")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "zero sends/keys/clients" in result.stdout
