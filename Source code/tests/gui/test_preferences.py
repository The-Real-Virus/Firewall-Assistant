"""Invented preferences with explicit directory-privacy doubles; no ACL acceptance."""

import json
from pathlib import Path

import pytest

from wfdiag.gui import preferences as module
from wfdiag.gui.preferences import Preferences, PreferenceStore, RecentCase


def recent(index: int, root: Path) -> RecentCase:
    return RecentCase(
        name=f"Operator case {index}",
        path=str(root / f"case-{index}"),
        case_id=f"synthetic-{index}",
        kind="analysis",
    )


def test_history_is_off_bounded_deduplicated_and_never_deletes_case_data(tmp_path) -> None:
    preferences = Preferences()
    assert not preferences.history_enabled and preferences.recent == ()
    with pytest.raises(ValueError):
        preferences.remembering(recent(1, tmp_path))
    preferences = preferences.changed(history_enabled=True)
    for index in range(25):
        preferences = preferences.remembering(recent(index, tmp_path))
    assert len(preferences.recent) == 20 and preferences.recent[0].case_id == "synthetic-24"
    preferences = preferences.remembering(recent(20, tmp_path))
    assert len(preferences.recent) == 20 and preferences.recent[0].case_id == "synthetic-20"
    evidence = tmp_path / "keep-this-case"
    evidence.mkdir()
    (evidence / "evidence.txt").write_text("synthetic evidence")
    preferences = preferences.changed(history_enabled=False, recent=[])
    assert (
        not preferences.recent and (evidence / "evidence.txt").read_text() == "synthetic evidence"
    )


@pytest.mark.parametrize(
    "value",
    [
        {"api_key": "secret"},
        {"ai_enabled": True},
        {"theme": "invented"},
        {
            "history_enabled": False,
            "recent": [{"name": "x", "path": "C:\\Case", "case_id": "x", "kind": "case"}],
        },
        {"work_root": "\\\\server\\share"},
    ],
)
def test_preferences_cannot_store_ai_keys_unknown_settings_or_unsafe_paths(value) -> None:
    with pytest.raises(ValueError):
        Preferences.model_validate_json(json.dumps(value))


def test_atomic_round_trip_failure_retains_old_file_and_no_plaintext_fallback(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(module, "verify_private_directory", lambda root: None)
    root = tmp_path / "private-double"
    monkeypatch.setattr(module, "create_private_directory", lambda path: path.mkdir())
    store = PreferenceStore(root)
    assert store.load() == Preferences() and not root.exists()
    store.save(Preferences(theme="Dark"))
    assert store.load().theme == "Dark"
    original = (root / "preferences-v1.json").read_bytes()

    def fail(*args):
        raise OSError("synthetic atomic replacement failure")

    monkeypatch.setattr(module.os, "replace", fail)
    with pytest.raises(OSError):
        store.save(Preferences(theme="Light"))
    assert (root / "preferences-v1.json").read_bytes() == original
    assert not tuple(root.glob(".preferences-*"))


@pytest.mark.parametrize(
    "content",
    [
        b'{"theme":"Dark","theme":"Light"}',
        b'{"theme":"Dark","api_key":"CANARY"}',
        b"x" * (128 * 1024 + 1),
        b'{"theme":',
    ],
)
def test_corrupt_preferences_raise_for_safe_startup_fallback(
    tmp_path, monkeypatch, content
) -> None:
    monkeypatch.setattr(module, "verify_private_directory", lambda root: None)
    (tmp_path / "preferences-v1.json").write_bytes(content)
    with pytest.raises(ValueError):
        PreferenceStore(tmp_path).load()
    assert (tmp_path / "preferences-v1.json").read_bytes() == content


def test_private_access_failure_never_writes_elsewhere(tmp_path, monkeypatch) -> None:
    def denied(root):
        raise PermissionError("synthetic privacy denial")

    monkeypatch.setattr(module, "verify_private_directory", denied)
    with pytest.raises(PermissionError):
        PreferenceStore(tmp_path).save(Preferences())
    assert list(tmp_path.iterdir()) == []
