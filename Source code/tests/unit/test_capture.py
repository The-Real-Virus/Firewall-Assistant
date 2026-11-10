"""Real bundle assembly from invented native streams; directory privacy is explicitly doubled."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.unit.native_policy_data import native_rule_data
from tests.unit.test_event_xml import XML
from wfdiag.collectors import capture
from wfdiag.collectors.process_runner import ProcessResult
from wfdiag.contracts.enums import Completeness, Direction, SourceState
from wfdiag.contracts.models import Host
from wfdiag.services.cancellation import CancellationToken, Cancelled
from wfdiag.storage.bundle import BundleError, VerifiedBundle

ROOT = Path(__file__).parents[2]
HOST = Host.model_validate_json((ROOT / "examples/synthetic-case/host.json").read_bytes())
STAMP = "2026-11-03T00:00:00Z"


def frames(source: str, values: list[object], state: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            "protocol_version": 1,
            "source": source,
            "kind": "started",
            "at_utc": STAMP,
            "window_start_utc": None,
            "window_end_utc": None,
        },
        *(
            {
                "protocol_version": 1,
                "source": source,
                "kind": "record",
                "at_utc": STAMP,
                "data": value,
            }
            for value in values
        ),
        {
            "protocol_version": 1,
            "source": source,
            "kind": "finished",
            "at_utc": STAMP,
            "state": state or ("complete" if values else "empty"),
            "count": len(values),
            "codes": [],
        },
    ]


def payloads() -> dict[str, list[dict[str, Any]]]:
    network = {
        "interface_index": 7,
        "name": "Synthetic interface",
        "addresses": ["192.0.2.1"],
        "active_profile": "Private",
        "state": "up",
        "source_ref": "network:1",
    }
    profiles = [
        {
            "Name": [name],
            "Enabled": ["True"],
            "DefaultInboundAction": ["Block"],
            "DefaultOutboundAction": ["Allow"],
            "AllowLocalFirewallRules": ["True"],
        }
        for name in ("Domain", "Private", "Public")
    ]
    return {
        "host": frames("host", [HOST.model_dump(mode="json")]) + frames("network", [network]),
        "policy": frames("profiles", profiles) + frames("rules", [native_rule_data()]),
        "events": frames("events", [XML.decode()]),
    }


class FakeResources:
    def __init__(self, data: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.data = payloads() if data is None else data
        self.calls: list[str] = []
        self.cancel_on: str | None = None
        self.timeout_on: str | None = None

    def __call__(
        self,
        resource: str,
        cancellation: CancellationToken,
        *,
        minutes: int = 10,
        stdout_consumer: Callable[[bytes], None] | None = None,
    ) -> ProcessResult:
        assert 1 <= minutes <= 60 and stdout_consumer is not None
        self.calls.append(resource)
        for value in self.data[resource]:
            data = (json.dumps(value, ensure_ascii=False) + "\n").encode()
            # Deliberately split inside non-ASCII UTF8 and JSON values.
            for offset in range(0, len(data), 7):
                stdout_consumer(data[offset : offset + 7])
        if resource == self.cancel_on:
            cancellation.request()
        return ProcessResult(b"", b"", 0, resource == self.timeout_on, False, False, False)


@pytest.fixture(autouse=True)
def private_directory_double(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture, "create_private_directory", lambda path: path.mkdir())


def build(path: Path, runner: FakeResources, token: CancellationToken | None = None):
    return capture.collect_case(
        path,
        10,
        token or CancellationToken(),
        lambda *_: None,
        host=HOST,
        runner=runner,
        mappings={r"\Device\HarddiskVolume7": "D:"},
    )


def test_source_assembly_round_trips_through_real_reader(tmp_path: Path) -> None:
    runner = FakeResources()
    path = tmp_path / "Invented case Ω"
    manifest = build(path, runner)
    assert manifest.completeness == Completeness.COMPLETE
    assert manifest.policy_change_observed is None
    assert runner.calls == ["host", "policy", "events"] and not (path / ".incomplete").exists()
    with VerifiedBundle(path) as bundle:
        assert len(bundle.rules) == 1 and len(bundle.profiles) == 3
        assert bundle.profiles[1].active is True
        events = tuple(bundle.iter_events())
        assert len(events) == 1
        event = events[0]
        assert event.application_canonical == r"D:\Apps\Example.exe"
        assert event.direction == Direction.UNKNOWN  # No native token validation invented.
        assert "CURRENT_DEVICE_MAPPING_OBSERVATION" in event.warnings
        assert event.source_ref == "events:1" and bundle.manifest.host == HOST


@pytest.mark.parametrize("state", ["access_denied", "unavailable", "error", "truncated"])
def test_failed_events_preserve_policy_and_incomplete_state(tmp_path: Path, state: str) -> None:
    data = payloads()
    data["events"] = frames("events", [], state)
    manifest = build(tmp_path / "case", FakeResources(data))
    assert manifest.completeness == Completeness.INCOMPLETE
    status = next(s for s in manifest.sources if s.source == "events")
    assert status.state.value == state and status.records == 0
    with VerifiedBundle(tmp_path / "case") as bundle:
        assert len(bundle.rules) == 1 and not tuple(bundle.iter_events())
        assert any(e.source == "events" for e in bundle.errors)


def test_malformed_event_does_not_hide_an_accepted_event(tmp_path: Path) -> None:
    data = payloads()
    data["events"] = frames("events", ["<!DOCTYPE Event><Event/>", XML.decode()])
    manifest = build(tmp_path / "case", FakeResources(data))
    assert manifest.completeness == Completeness.INCOMPLETE
    with VerifiedBundle(tmp_path / "case") as bundle:
        events = tuple(bundle.iter_events())
        assert len(events) == 1 and events[0].source_ref == "events:2"


def test_timeout_and_unterminated_protocol_never_look_empty(tmp_path: Path) -> None:
    data = payloads()
    data["policy"] = data["policy"][:-1]
    runner = FakeResources(data)
    runner.timeout_on = "policy"
    manifest = build(tmp_path / "case", runner)
    assert manifest.completeness == Completeness.INCOMPLETE
    status = next(s for s in manifest.sources if s.source == "rules")
    assert status.state == SourceState.ERROR and "COLLECTOR_TIMEOUT" in status.warnings


def test_cancel_retains_marker_and_previous_destinations(tmp_path: Path) -> None:
    path = tmp_path / "interrupted"
    runner = FakeResources()
    runner.cancel_on = "policy"
    with pytest.raises(Cancelled):
        build(path, runner)
    assert (path / ".incomplete").exists() and not (path / "manifest.json").exists()
    with pytest.raises(BundleError), VerifiedBundle(path):
        pass
    with pytest.raises(FileExistsError):
        build(path, FakeResources())


def test_ordinary_import_refuses_even_valid_authoring_marker(tmp_path: Path) -> None:
    path = tmp_path / "case"
    build(path, FakeResources())
    (path / ".incomplete").write_bytes(b'{"operation":"collect","status":"incomplete"}\n')
    with pytest.raises(BundleError), VerifiedBundle(path):
        pass


def test_local_line_cap_is_incomplete_not_a_silent_drop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(capture, "MAX_EVENT_LINE_BYTES", 10)
    manifest = build(tmp_path / "case", FakeResources())
    assert manifest.completeness == Completeness.INCOMPLETE
    assert next(s for s in manifest.sources if s.source == "events").state == SourceState.TRUNCATED
