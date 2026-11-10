"""Real worker pipes/services with a directory-privacy double, not native ACL acceptance."""

import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from wfdiag.contracts.desktop_job import EventDecoder, decode_request
from wfdiag.version import __version__

ROOT = Path(__file__).parents[2]
BOOTSTRAP = "from pathlib import Path; import sys; from wfdiag.services import desktop_worker as w; w.verify_private_directory=lambda path:None; raise SystemExit(w.run_desktop_job(Path(sys.argv[1])))"


def request_file(tmp_path: Path, **changes: object) -> tuple[Path, str, Path]:
    identifier = str(uuid4())
    directory = tmp_path / identifier
    directory.mkdir(mode=0o700)
    output = tmp_path / "share.json"
    data = {
        "protocol_version": 1,
        "job_id": identifier,
        "operation": "report",
        "expected_engine_version": __version__,
        "parameters": {
            "analysis": str(ROOT / "examples/expected-analysis.json"),
            "mode": "share",
            "out": str(output),
        },
    }
    data.update(changes)
    path = directory / "request.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path, identifier, output


def test_worker_report_roundtrip_requires_terminal_and_process_agreement(tmp_path: Path) -> None:
    path, identifier, output = request_file(tmp_path)
    process = subprocess.Popen(
        [sys.executable, "-c", BOOTSTRAP, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None and process.stdin is not None
    decoder = EventDecoder(identifier)
    events = []
    while line := process.stdout.readline():
        events.extend(decoder.feed(line))
    assert process.wait(timeout=10) == 0
    process.stdin.close()
    assert process.stderr is not None and process.stderr.read() == b""
    decoder.finish()
    assert events[0].type == "started" and events[-1].type == "completed"
    assert events[-1].payload.output == str(output)
    assert json.loads(output.read_bytes())["mode"] == "share"


def test_worker_rejects_version_mismatch_without_writing_result(tmp_path: Path) -> None:
    path, identifier, output = request_file(tmp_path, expected_engine_version="999.0.0")
    process = subprocess.Popen(
        [sys.executable, "-c", BOOTSTRAP, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    decoder = EventDecoder(identifier)
    events = []
    while line := process.stdout.readline():
        events.extend(decoder.feed(line))
    assert process.wait(timeout=10) == 2
    assert process.stdin is not None
    process.stdin.close()
    decoder.finish()
    assert events[-1].type == "failed" and not output.exists()


@pytest.mark.parametrize("control", ["eof", "cancel", "malformed"])
def test_worker_parent_disconnect_or_cancel_never_completes_a_result(
    tmp_path: Path, control: str
) -> None:
    path, identifier, output = request_file(tmp_path)
    bootstrap = """from pathlib import Path
import sys,time
from wfdiag.services import desktop_worker as w
w.verify_private_directory=lambda path:None
original=w.operations.execute
def delayed(request,cancellation,progress):
    for _ in range(200):
        cancellation.check()
        time.sleep(0.01)
    return original(request,cancellation,progress)
w.operations.execute=delayed
raise SystemExit(w.run_desktop_job(Path(sys.argv[1])))
"""
    data = (
        b""
        if control == "eof"
        else (
            json.dumps({"protocol_version": 1, "job_id": identifier, "type": "cancel"}) + "\n"
        ).encode()
        if control == "cancel"
        else b"not-json\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", bootstrap, str(path)],
        input=data,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 5
    decoder = EventDecoder(identifier)
    events = decoder.feed(result.stdout)
    decoder.finish()
    assert events[-1].type == "cancelled" and events[-1].payload.cleanup_confirmed
    assert not output.exists() and result.stderr == b""


def test_duplicate_request_keys_cannot_change_an_operation() -> None:
    with pytest.raises(ValueError, match="(?i)duplicate"):
        decode_request(b'{"operation":"collect","operation":"report"}')
