import os
from pathlib import Path

import pytest

from wfdiag.storage.atomic_write import write_new_bytes


def test_new_file_finalizes_without_temp_residue(tmp_path: Path) -> None:
    destination = tmp_path / "result.json"
    write_new_bytes(destination, b"{}")
    assert destination.read_bytes() == b"{}"
    assert list(tmp_path.iterdir()) == [destination]


def test_existing_output_is_never_replaced(tmp_path: Path) -> None:
    destination = tmp_path / "result.json"
    destination.write_bytes(b"keep original")
    with pytest.raises(FileExistsError):
        write_new_bytes(destination, b"new")
    assert destination.read_bytes() == b"keep original"


def test_actual_output_bytes_are_bounded_before_writing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="byte budget"):
        write_new_bytes(tmp_path / "new", b"x" * 101, byte_limit=100)
    assert not list(tmp_path.iterdir())


def test_alternate_stream_output_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        write_new_bytes(tmp_path / "result.json:stream", b"{}")


def test_interrupted_flush_never_commits_a_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_flush(descriptor: int) -> None:
        raise OSError("synthetic storage interruption")

    monkeypatch.setattr(os, "fsync", failed_flush)
    with pytest.raises(OSError):
        write_new_bytes(tmp_path / "result.json", b'{"complete":true}')
    assert list(tmp_path.iterdir()) == []


def test_destination_created_during_finalize_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "result.json"
    native_link = os.link

    def competing_destination(source: Path, target: Path, **kwargs: object) -> None:
        target.write_bytes(b"competing original")
        native_link(source, target, follow_symlinks=False)

    monkeypatch.setattr(os, "link", competing_destination)
    with pytest.raises(FileExistsError):
        write_new_bytes(destination, b"new result")
    assert destination.read_bytes() == b"competing original"
    assert list(tmp_path.iterdir()) == [destination]
