import json

import pytest

from wfdiag.collectors.protocol import CollectionStream

START = {
    "protocol_version": 1,
    "kind": "started",
    "source": "profiles",
    "at_utc": "2026-11-03T00:00:00Z",
    "window_start_utc": None,
    "window_end_utc": None,
}
END = {
    "protocol_version": 1,
    "kind": "finished",
    "source": "profiles",
    "at_utc": "2026-11-03T00:00:01Z",
    "state": "empty",
    "count": 0,
    "codes": [],
}


def wire(*values: object) -> bytes:
    return b"".join(json.dumps(value).encode() + b"\n" for value in values)


def test_bom_and_chunk_boundaries_preserve_empty_status() -> None:
    frames = []
    stream = CollectionStream(("profiles",), frames.append)
    for byte in b"\xef\xbb\xbf" + wire(START, END):
        stream.feed(bytes([byte]))
    stream.finish()
    assert len(frames) == 2 and frames[-1].kind == "finished"
    assert frames[-1].state == "empty"


@pytest.mark.parametrize(
    "ending",
    [
        {**END, "count": 1},
        {**END, "source": "rules"},
        {**END, "state": "complete"},
        {**END, "protocol_version": True},
        {**END, "at_utc": "2026-11-02T00:00:00Z"},
    ],
)
def test_mismatched_completion_cannot_be_repaired(ending: object) -> None:
    stream = CollectionStream(("profiles",), lambda _: None)
    stream.feed(wire(START))
    with pytest.raises(ValueError):
        stream.feed(wire(ending))
    with pytest.raises(ValueError):
        stream.feed(wire(END))
    with pytest.raises(ValueError):
        stream.finish()


@pytest.mark.parametrize(
    "data",
    [
        wire(START),
        wire(START) + b'{"kind":',
        wire(START, END) + b"junk",
        b'{"kind":"started","kind":"finished"}\n',
        b"x" * (512 * 1024 + 1),
    ],
)
def test_truncation_duplicate_keys_and_oversize_cannot_complete(data: bytes) -> None:
    stream = CollectionStream(("profiles",), lambda _: None)
    with pytest.raises(ValueError):
        stream.feed(data)
        stream.finish()
