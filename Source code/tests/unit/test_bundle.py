import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from wfdiag.storage.bundle import BundleError, VerifiedBundle
from wfdiag.storage.json_input import checked_json


def create_case(parent: Path) -> Path:
    root = parent / "synthetic case Ω"
    root.mkdir()
    examples = json.loads(
        (Path(__file__).parents[2] / "examples/contract-examples.json").read_text(encoding="utf-8")
    )["records"]
    host = examples["host"]
    profiles = [
        {
            "profile": profile,
            "enabled": True,
            "active": profile == "Private",
            "default_inbound": "Block",
            "default_outbound": "Allow",
            "allow_local_rule_merge": True,
            "source_ref": "profiles:" + profile,
        }
        for profile in ["Domain", "Private", "Public"]
    ]
    contents = {
        "host.json": json.dumps(host).encode(),
        "profiles.json": json.dumps(profiles).encode(),
        "rules.json": b"[]",
        "events.ndjson": json.dumps(examples["event"]).encode() + b"\n",
        "collection-errors.json": b"[]",
    }
    files = []
    for name, data in contents.items():
        (root / name).write_bytes(data)
        files.append(
            {"filename": name, "byte_length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
    sources = [
        {
            "source": name,
            "state": "complete",
            "window_start_utc": None,
            "window_end_utc": None,
            "records": {"host": 1, "profiles": 3, "events": 1}.get(name, 0),
            "warnings": [],
        }
        for name in ["host", "profiles", "rules", "events", "collection-errors"]
    ]
    manifest = {
        "schema_version": "1.0",
        "run_id": "synthetic-bundle",
        "collector_version": "1.0.0rc1",
        "collected_at_utc": "2026-11-01T00:10:00Z",
        "host": host,
        "completeness": "complete",
        "sources": sources,
        "files": files,
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def rewrite_manifest(root: Path, mutation: object) -> None:
    assert callable(mutation)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    mutation(manifest)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_real_opened_bundle_validates_hashes_and_events(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    with VerifiedBundle(root) as bundle:
        assert bundle.manifest.run_id == "synthetic-bundle"
        assert len(bundle.profiles) == 3
        assert bundle.rules == ()
        assert [e.record_id for e in bundle.iter_events()] == [1]
        bundle.check_unchanged()


def test_corrupt_hash_never_becomes_empty_analysis(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    path = root / "events.ndjson"
    data = path.read_bytes()
    path.write_bytes(data.replace(b"4660", b"4661"))
    with pytest.raises(BundleError, match="hash"), VerifiedBundle(root):
        pass


@pytest.mark.parametrize("name", ["unexpected.json", "nested", "archive.zip"])
def test_unknown_root_entries_are_rejected(tmp_path: Path, name: str) -> None:
    root = create_case(tmp_path)
    (root / name).write_bytes(b"not accepted")
    with pytest.raises(BundleError, match="unexpected"), VerifiedBundle(root):
        pass


def test_missing_source_is_rejected(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    (root / "rules.json").unlink()
    with pytest.raises(BundleError), VerifiedBundle(root):
        pass


@pytest.mark.parametrize(
    "filename", ["../escape", "C:\\outside.json", "host.json:secret", "subdir/host.json"]
)
def test_manifest_cannot_select_a_different_file(tmp_path: Path, filename: str) -> None:
    root = create_case(tmp_path)
    rewrite_manifest(root, lambda m: m["files"][0].update(filename=filename))
    with pytest.raises(BundleError), VerifiedBundle(root):
        pass


def test_event_count_mismatch_is_not_success(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    rewrite_manifest(root, lambda m: m["sources"][3].update(records=2))
    with VerifiedBundle(root) as bundle, pytest.raises(BundleError, match="count"):
        list(bundle.iter_events())


def test_hardlink_alias_is_rejected(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    os.link(root / "events.ndjson", tmp_path / "alias.ndjson")
    with pytest.raises((BundleError, ValueError)), VerifiedBundle(root):
        pass


@pytest.mark.windows
@pytest.mark.skipif(
    sys.platform != "win32", reason="Windows file sharing is a native-only observation"
)
def test_opened_windows_source_denies_a_concurrent_writer(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    with VerifiedBundle(root), pytest.raises(PermissionError), (root / "events.ndjson").open("r+b"):
        pass


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b"[" * 25 + b"0" + b"]" * 25,
        b'{"n":NaN}',
        b'{"n":1e999}',
        b'{"n":' + b"9" * 21 + b"}",
    ],
)
def test_hostile_json_is_rejected_before_models(raw: bytes) -> None:
    with pytest.raises(ValueError):
        checked_json(raw, byte_limit=1024)


def test_json_brackets_inside_strings_do_not_consume_depth() -> None:
    value = checked_json(b'{"message":"[brackets] and \\"quotes\\""}', byte_limit=1024)
    assert value == {"message": '[brackets] and "quotes"'}


@pytest.mark.parametrize("size", [0, 128 * 1024 * 1024 + 1])
def test_false_declared_lengths_fail_closed(tmp_path: Path, size: int) -> None:
    root = create_case(tmp_path)
    rewrite_manifest(root, lambda m: m["files"][0].update(byte_length=size))
    with pytest.raises(BundleError), VerifiedBundle(root):
        pass


def test_unknown_schema_never_migrates_implicitly(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    rewrite_manifest(root, lambda m: m.update(schema_version="2.0"))
    with pytest.raises(BundleError), VerifiedBundle(root):
        pass


def test_invalid_utf8_with_matching_hash_is_rejected(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    data = b"\xff"
    (root / "rules.json").write_bytes(data)
    rewrite_manifest(
        root,
        lambda m: next(f for f in m["files"] if f["filename"] == "rules.json").update(
            byte_length=1, sha256=hashlib.sha256(data).hexdigest()
        ),
    )
    with pytest.raises(BundleError), VerifiedBundle(root):
        pass


def test_actual_streamed_case_budget_includes_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import wfdiag.storage.bundle as module

    root = create_case(tmp_path)
    manifest_size = (root / "manifest.json").stat().st_size
    monkeypatch.setattr(module, "MAX_TOTAL_BYTES", manifest_size + 1)
    with pytest.raises(BundleError, match="budget"), VerifiedBundle(root):
        pass


def test_source_record_counts_are_not_trusted(tmp_path: Path) -> None:
    root = create_case(tmp_path)
    rewrite_manifest(root, lambda m: m["sources"][1].update(records=2))
    with pytest.raises(BundleError, match="count"), VerifiedBundle(root):
        pass
