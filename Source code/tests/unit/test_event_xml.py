import json

import pytest

from wfdiag.contracts.enums import Direction
from wfdiag.contracts.models import Event
from wfdiag.parsers.deduplication import deduplicate_events
from wfdiag.parsers.event_xml import EventParseError, canonical_application, parse_event_xml

XML = b"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5157</EventID><Version>1</Version><TimeCreated SystemTime="2026-11-01T00:00:00.123456700Z"/><EventRecordID>123</EventRecordID></System><EventData><Data Name="Application">\\Device\\HarddiskVolume7\\Apps\\Example.exe</Data><Data Name="Direction">%%14593</Data><Data Name="ProcessID">0x1234</Data><Data Name="SourceAddress">2001:db8::1</Data><Data Name="SourcePort">50001</Data><Data Name="DestAddress">2001:db8::2</Data><Data Name="DestPort">443</Data><Data Name="Protocol">6</Data><Data Name="FilterRTID">99</Data><Data Name="ExtraFutureField">preserve me</Data></EventData></Event>"""


def test_named_fields_ipv6_explicit_hex_pid_and_unknowns() -> None:
    event = parse_event_xml(XML, "events:1")
    assert event.pid_raw == "0x1234" and event.pid_value == 4660
    assert event.source_address == "2001:db8::1" and event.destination_port == 443
    assert event.unknown_fields["eventdata:ExtraFutureField"] == "preserve me"
    assert event.unknown_fields["system_time_raw"].endswith("123456700Z")
    assert event.application_canonical is None
    assert event.direction == Direction.UNKNOWN
    assert event.filter_origin is None


def test_fixture_mapping_does_not_guess_native_drive_or_direction() -> None:
    event = parse_event_xml(
        XML,
        "events:1",
        device_mappings={r"\Device\HarddiskVolume7": "D:"},
        verified_direction_tokens={"%%14593": Direction.OUTBOUND},
    )
    assert event.application_canonical == r"D:\Apps\Example.exe"
    assert event.direction == Direction.OUTBOUND
    assert event.filter_runtime_id == 99


def test_native_prefix_requires_boundary_and_unambiguous_mapping() -> None:
    raw = r"\Device\HarddiskVolume7\Apps\Example.exe"
    assert canonical_application(raw, {r"\Device\HarddiskVolume70": "C:"}) is None
    assert (
        canonical_application(
            raw, {r"\Device\HarddiskVolume7": "C:", r"\device\harddiskvolume7": "D:"}
        )
        is None
    )


def test_5152_process_id_case_is_supported() -> None:
    event = parse_event_xml(
        XML.replace(b"<EventID>5157", b"<EventID>5152")
        .replace(b'Name="ProcessID"', b'Name="ProcessId"')
        .replace(b"0x1234", b"4556"),
        "events:2",
    )
    assert event.event_id == 5152 and event.pid_value == 4556


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: b'<!DOCTYPE Event [<!ENTITY x "expand">]>' + data,
        lambda data: data.replace(b'Name="ProcessID"', b'Name="Direction"'),
        lambda data: data.replace(b"0x1234", b"9" * 5000),
        lambda data: data.replace(b"<EventID>5157", b"<EventID>5156"),
        lambda data: data.replace(
            b'SystemTime="2026-11-01T00:00:00.123456700Z"', b'SystemTime="2026-11-01T00:00:00"'
        ),
        lambda data: data.replace(b"Microsoft-Windows-Security-Auditing", b"Unrelated-provider"),
        lambda data: data[:-20],
    ],
)
def test_malformed_or_unsafe_xml_is_rejected(mutation: object) -> None:
    assert callable(mutation)
    with pytest.raises(ValueError):
        parse_event_xml(mutation(XML), "events:bad")


def test_oversized_actual_xml_fails_before_parsing() -> None:
    with pytest.raises(EventParseError, match="BYTE_LIMIT"):
        parse_event_xml(b" " * (64 * 1024 + 1), "events:bad")


def test_invalid_numbers_stay_unknown_with_raw_evidence() -> None:
    event = parse_event_xml(
        XML.replace(b">50001<", b">999999999999999999999999<").replace(b">0x1234<", b">0xNOTHEX<"),
        "events:bad-number",
    )
    assert event.source_port is None and event.pid_value is None
    assert event.pid_raw == "0xNOTHEX"
    assert event.unknown_fields["raw:SourcePort"] == "999999999999999999999999"


def test_distinct_attempts_are_not_deduplicated() -> None:
    first = parse_event_xml(XML, "events:1")
    second = Event.model_validate_json(
        first.model_dump_json()
        .replace('"record_id":123', '"record_id":124')
        .replace('"events:1"', '"events:2"')
    )
    assert len(deduplicate_events([first, second])) == 2


def test_exact_duplicate_retains_all_source_references() -> None:
    first = parse_event_xml(XML, "events:1")
    payload = first.model_dump(mode="json")
    payload["source_ref"] = "events:duplicate"
    duplicate = Event.model_validate_json(json.dumps(payload))
    groups = deduplicate_events([first, duplicate])
    assert len(groups) == 1 and groups[0].source_refs == ("events:1", "events:duplicate")
