import hashlib
from pathlib import Path

import pytest

from wfdiag.storage.stream_output import NewSource


def test_stream_is_bounded_and_does_not_finalize_interrupted_bytes(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    with pytest.raises(ValueError, match="budget"), NewSource(path, 5) as source:
        source.write(b"12345")
        source.write(b"6")
    assert not path.exists() and not list(tmp_path.iterdir())


def test_stream_finalizes_exact_bytes_and_refuses_competing_destination(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    with NewSource(path, 20) as source:
        source.write(b"[")
        source.write(b"{}]")
    assert source.finished and path.read_bytes() == b"[{}]"
    assert source.digest.hexdigest() == hashlib.sha256(path.read_bytes()).hexdigest()
    other = tmp_path / "events.ndjson"
    with pytest.raises(FileExistsError), NewSource(other, 20) as race:
        race.write(b"new bytes")
        other.write_bytes(b"owner file")
    assert other.read_bytes() == b"owner file"
    assert not list(tmp_path.glob(".wfdiag-*"))
