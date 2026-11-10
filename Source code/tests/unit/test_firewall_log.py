from datetime import timedelta, timezone

import pytest

from wfdiag.parsers.firewall_log import MAX_LINE_BYTES, parse_firewall_log

HEADER = b"#Fields: date time action protocol src-ip dst-ip src-port dst-port path\n"
RECORD = b"2026-11-01 10:00:00 DROP TCP 192.0.2.1 192.0.2.2 50001 443 <script>\n"


def test_log_preserves_unknown_time_and_untrusted_fields_without_identity() -> None:
    result = parse_firewall_log([b"\xef\xbb\xbf#Software: Windows Firewall\n", HEADER, RECORD])
    (record,) = result.observations
    assert record.timestamp_utc is None
    assert record.time_basis == "unknown"
    assert record.source_ref == "firewall-log:3"
    assert record.destination_port == 443
    assert dict(record.fields)["path"] == "<script>"
    assert not result.application_identity_available
    assert not result.proposal_eligible


def test_reordered_columns_and_recorded_utc() -> None:
    result = parse_firewall_log(
        [
            b"#Time Format: UTC\n",
            b"#Fields: action time date protocol dst-ip src-ip dst-port src-port\n",
            b"DROP 10:00:00 2026-11-01 TCP 2001:db8::2 2001:db8::1 443 50001\n",
        ]
    )
    (record,) = result.observations
    assert record.timestamp_utc.isoformat() == "2026-11-01T10:00:00+00:00"
    assert record.destination_address == "2001:db8::2"


def test_local_header_never_uses_analyzing_machine_timezone() -> None:
    result = parse_firewall_log([b"#Time Format: Local\n", HEADER, RECORD])
    assert result.observations[0].timestamp_utc is None
    recorded = parse_firewall_log([HEADER, RECORD], recorded_offset=timezone(timedelta(hours=5)))
    assert recorded.observations[0].timestamp_utc.hour == 5


def test_new_header_section_does_not_inherit_old_columns_or_utc() -> None:
    result = parse_firewall_log(
        [b"#Time Format: UTC\n", HEADER, RECORD, b"#Version: 1.5\n", RECORD, HEADER, RECORD]
    )
    assert len(result.observations) == 2
    assert result.observations[0].time_basis == "recorded_utc"
    assert result.observations[1].time_basis == "unknown"
    assert result.rejected[0].source_ref == "firewall-log:5"


@pytest.mark.parametrize(
    "raw",
    [
        RECORD.replace(b"50001", b"999999"),
        RECORD.replace(b"192.0.2.1", b"2001:db8::1"),
        b"\xff\n",
        RECORD.replace(b"10:00:00", b"99:99:99"),
    ],
)
def test_invalid_records_preserve_rejection_reference(raw: bytes) -> None:
    result = parse_firewall_log([HEADER, raw])
    assert not result.observations
    assert result.rejected[0].source_ref == "firewall-log:2"


def test_missing_header_and_unterminated_final_record_are_distinct() -> None:
    result = parse_firewall_log([RECORD, HEADER, RECORD.rstrip(b"\n")])
    assert [r.reason for r in result.rejected] == ["missing_fields_header", "unterminated_record"]
    assert result.truncated


def test_absent_values_comments_and_empty_file() -> None:
    assert not parse_firewall_log([]).observations
    result = parse_firewall_log([b"# comment\n", b"\n", HEADER, RECORD.replace(b"50001", b"-")])
    assert result.observations[0].source_port is None
    assert not result.rejected


def test_huge_line_is_rejected_before_decode_and_later_records_survive() -> None:
    result = parse_firewall_log([HEADER, b"x" * (MAX_LINE_BYTES + 1), RECORD])
    assert result.truncated
    assert result.rejected[0].reason == "line_budget_exceeded"
    assert len(result.observations) == 1
