"""Slow policy reads must not move the event window past the reproduced failure."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from wfdiag.collectors import audit_policy, capture
from wfdiag.collectors.process_runner import ProcessResult
from wfdiag.services.cancellation import CancellationToken


def test_native_event_window_is_anchored_before_other_sources(monkeypatch, tmp_path):
    from wfdiag.contracts.models import Host

    anchor = datetime(2026, 11, 8, 7, 0, tzinfo=UTC)
    host = Host.model_validate_json(
        (Path(__file__).parents[2] / "examples/synthetic-case/host.json").read_bytes()
    )
    monkeypatch.setattr(capture, "observed_host", lambda: host)
    monkeypatch.setattr(capture, "current_device_mappings", dict)
    monkeypatch.setattr(
        audit_policy, "failure_audit_codes", lambda: ("AUDIT_5157_FAILURE_DISABLED",)
    )

    class Clock:
        current = anchor

        @classmethod
        def now(cls, tz):
            return cls.current

    monkeypatch.setattr(capture, "datetime", Clock)
    seen = []

    def resource(name, token, **kwargs):
        seen.append((name, kwargs))
        return ProcessResult(b"", b"", 0, False, False, False, False)

    monkeypatch.setattr(capture, "run_resource", resource)
    result = object()

    def assembled(path, minutes, token, progress, **kwargs):
        assert kwargs["audit_codes"] == ("AUDIT_5157_FAILURE_DISABLED",)
        kwargs["runner"]("host", token)
        Clock.current += timedelta(minutes=2)
        kwargs["runner"]("events", token, minutes=1)
        return result

    monkeypatch.setattr(capture, "collect_case", assembled)
    assert (
        capture.collect_native_case(tmp_path / "case", 1, CancellationToken(), lambda *_: None)
        is result
    )
    assert seen[0][1]["event_end"] is None
    assert seen[1][1]["event_end"] == anchor
    assert seen[1][1]["minutes"] == 1
