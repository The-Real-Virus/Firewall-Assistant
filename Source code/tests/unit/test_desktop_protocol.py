import json

import pytest
from pydantic import ValidationError

from wfdiag.contracts.desktop_job import EventDecoder, decode_request


def frame(kind: str, sequence: int, payload: dict[str, object], job: str = "job-1") -> bytes:
    return (
        json.dumps(
            {
                "protocol_version": 1,
                "job_id": job,
                "sequence": sequence,
                "type": kind,
                "payload": payload,
            }
        )
        + "\n"
    ).encode()


START = frame("started", 1, {"engine_version": "1.0.0rc1"})
DONE = frame(
    "completed",
    2,
    {"output": r"C:\Private\result.json", "completeness": "complete", "exit_code": 0},
)


def test_real_serialized_frames_survive_chunk_boundaries() -> None:
    decoder = EventDecoder("job-1")
    stream = START + DONE
    events = []
    for i in range(0, len(stream), 7):
        events.extend(decoder.feed(stream[i : i + 7]))
    decoder.finish()
    assert [event.type for event in events] == ["started", "completed"]


@pytest.mark.parametrize(
    "bad",
    [
        frame("started", 1, {"engine_version": "1.0.0rc1"}, "wrong-job"),
        frame("started", 2, {"engine_version": "1.0.0rc1"}),
        DONE,
        b"\xff\n",
        b"{}\n",
        b"\n",
        b"x" * (16 * 1024 + 1),
        b"x" * (2 * 1024 * 1024 + 1),
    ],
)
def test_bad_stream_poisoning_prevents_later_success(bad: bytes) -> None:
    decoder = EventDecoder("job-1")
    with pytest.raises(ValueError):
        decoder.feed(bad)
    with pytest.raises(ValueError):
        decoder.feed(START + DONE)


def test_completion_after_cancel_is_rejected() -> None:
    decoder = EventDecoder("job-1")
    decoder.feed(START)
    decoder.feed(frame("cancelled", 2, {"cleanup_confirmed": True}))
    with pytest.raises(ValueError):
        decoder.feed(
            frame(
                "completed",
                3,
                {"output": r"C:\Private\result.json", "completeness": "complete", "exit_code": 0},
            )
        )


def test_incomplete_exit_cannot_have_complete_payload() -> None:
    decoder = EventDecoder("job-1")
    decoder.feed(START)
    with pytest.raises(ValidationError):
        decoder.feed(
            frame(
                "completed",
                2,
                {"output": r"C:\Private\result.json", "completeness": "complete", "exit_code": 5},
            )
        )


def test_eof_without_completion_is_failure() -> None:
    decoder = EventDecoder("job-1")
    decoder.feed(START)
    with pytest.raises(ValueError):
        decoder.finish()


@pytest.mark.parametrize(
    "patch",
    [
        {"operation": "apply"},
        {"operation": "ai"},
        {"protocol_version": 2},
        {"protocol_version": True},
        {"protocol_version": 1.0},
        {"executable": "anything.exe"},
        {"parameters": {"out": "relative.json"}},
        {"parameters": {"out": r"C:\Private\..\escape.json"}},
        {"parameters": {"out": r"\\server\share\result.json"}},
        {"parameters": {"out": r"C:\Private\result.json:stream"}},
    ],
)
def test_only_fixed_local_typed_requests_are_accepted(patch: dict[str, object]) -> None:
    request = {
        "protocol_version": 1,
        "job_id": "job-1",
        "operation": "doctor",
        "expected_engine_version": "1.0.0rc1",
        "parameters": {"out": r"C:\Private\doctor.json"},
    }
    request.update(patch)
    with pytest.raises(ValidationError):
        decode_request(json.dumps(request).encode())


def test_request_cannot_exceed_actual_byte_limit() -> None:
    with pytest.raises(ValueError, match="byte budget"):
        decode_request(b" " * (64 * 1024 + 1))
