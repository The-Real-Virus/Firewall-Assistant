"""Normalize named Security event XML while preserving unresolved identities and fields."""

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from datetime import datetime
from ipaddress import ip_address

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from wfdiag.contracts.base import utc_only, windows_program
from wfdiag.contracts.enums import Direction
from wfdiag.contracts.models import Event

NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": NAMESPACE}
MAX_XML_BYTES = 64 * 1024
KNOWN_FIELDS = {
    "ProcessID",
    "ProcessId",
    "Application",
    "Direction",
    "SourceAddress",
    "SourcePort",
    "DestAddress",
    "DestPort",
    "Protocol",
    "FilterRTID",
    "FilterOrigin",
    "InterfaceIndex",
}


class EventParseError(ValueError):
    """Safe parse code. The raw XML is never included in the public exception."""


def canonical_application(raw: str, device_mappings: Mapping[str, str]) -> str | None:
    try:
        return windows_program(raw)
    except ValueError:
        pass
    candidates = set()
    for device, drive in device_mappings.items():
        if not device.casefold().startswith("\\device\\") or not re.fullmatch(r"[A-Za-z]:", drive):
            continue
        if raw.casefold().startswith(device.casefold().rstrip("\\") + "\\"):
            candidate = drive.upper() + raw[len(device.rstrip("\\")) :]
            try:
                candidates.add(windows_program(candidate))
            except ValueError:
                continue
    return next(iter(candidates)) if len(candidates) == 1 else None


def _integer(raw: str | None, maximum: int, *, hexadecimal: bool = False) -> int | None:
    if raw is None:
        return None
    value = raw.strip()
    if re.fullmatch(r"[0-9]{1,20}", value):
        number = int(value, 10)
    elif hexadecimal and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
        number = int(value, 16)
    else:
        return None
    return number if number <= maximum else None


def _one(parent: ET.Element, name: str) -> ET.Element:
    elements = parent.findall("e:" + name, NS)
    if len(elements) != 1:
        raise EventParseError("MISSING_OR_DUPLICATE_" + name.upper())
    return elements[0]


def parse_event_xml(
    xml: bytes,
    source_ref: str,
    *,
    device_mappings: Mapping[str, str] | None = None,
    verified_direction_tokens: Mapping[str, Direction] | None = None,
) -> Event:
    if len(xml) > MAX_XML_BYTES:
        raise EventParseError("EVENT_XML_BYTE_LIMIT")
    try:
        root = SafeET.fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, ET.ParseError, ValueError) as exc:
        raise EventParseError("INVALID_OR_UNSAFE_XML") from exc
    if root.tag != "{" + NAMESPACE + "}Event":
        raise EventParseError("UNSUPPORTED_EVENT_NAMESPACE")
    stack = [(root, 0)]
    count = 0
    while stack:
        element, depth = stack.pop()
        count += 1
        if depth > 16 or count > 512:
            raise EventParseError("EVENT_XML_STRUCTURE_LIMIT")
        stack.extend((child, depth + 1) for child in element)
    system = _one(root, "System")
    provider = _one(system, "Provider").get("Name")
    if provider != "Microsoft-Windows-Security-Auditing":
        raise EventParseError("UNSUPPORTED_PROVIDER")
    event_id = _integer(_one(system, "EventID").text, 65535)
    if event_id not in (5157, 5152):
        raise EventParseError("UNSUPPORTED_EVENT_ID")
    version = _integer(_one(system, "Version").text, 255)
    record_id = _integer(_one(system, "EventRecordID").text, 2**64 - 1)
    timestamp_raw = _one(system, "TimeCreated").get("SystemTime")
    if version is None or record_id is None or timestamp_raw is None or len(timestamp_raw) > 100:
        raise EventParseError("INVALID_EVENT_METADATA")
    try:
        timestamp = utc_only(datetime.fromisoformat(timestamp_raw))
    except ValueError as exc:
        raise EventParseError("INVALID_UTC_SYSTEM_TIME") from exc
    data: dict[str, str] = {}
    for field in _one(root, "EventData"):
        name = field.get("Name")
        if (
            field.tag != "{" + NAMESPACE + "}Data"
            or name is None
            or not 1 <= len(name) <= 118
            or len(field)
        ):
            raise EventParseError("INVALID_NAMED_EVENT_FIELD")
        if name in data:
            raise EventParseError("DUPLICATE_EVENT_FIELD")
        if len(data) >= 64:
            raise EventParseError("EVENT_FIELD_COUNT_LIMIT")
        value = field.text or ""
        if len(value) > 4096:
            raise EventParseError("EVENT_FIELD_LENGTH_LIMIT")
        data[name] = value
    if "ProcessID" in data and "ProcessId" in data:
        raise EventParseError("AMBIGUOUS_PID_FIELDS")
    warnings = []
    unknown = {"system_time_raw": timestamp_raw}
    for name, value in data.items():
        if name not in KNOWN_FIELDS:
            if len(unknown) >= 50:
                warnings.append("UNKNOWN_FIELDS_TRUNCATED")
                break
            unknown["eventdata:" + name] = value[:500]
            if len(value) > 500:
                warnings.append("UNKNOWN_FIELD_VALUE_TRUNCATED")
    if version not in (0, 1):
        warnings.append("EVENT_VERSION_UNVERIFIED")
    if re.search(r"\.\d{7,}", timestamp_raw):
        warnings.append("SUBMICROSECOND_TIME_PRESERVED_AS_RAW")
    direction_raw = data.get("Direction")
    direction = (verified_direction_tokens or {}).get(direction_raw or "", Direction.UNKNOWN)
    if direction == Direction.UNKNOWN:
        warnings.append("DIRECTION_UNRESOLVED")
        if direction_raw is not None:
            unknown["direction_raw"] = direction_raw[:500]
    application_raw = data.get("Application") or None
    canonical = (
        canonical_application(application_raw, device_mappings or {}) if application_raw else None
    )
    if canonical is None:
        warnings.append("APPLICATION_IDENTITY_UNRESOLVED")
    pid_raw = data.get("ProcessID", data.get("ProcessId"))
    if pid_raw is not None and len(pid_raw) > 500:
        raise EventParseError("PID_FIELD_LENGTH_LIMIT")
    pid = _integer(pid_raw, 2**32 - 1, hexadecimal=True)
    if pid is None:
        warnings.append("PID_UNRESOLVED")

    def integer_field(name: str, maximum: int) -> int | None:
        value = _integer(data.get(name), maximum)
        if value is None:
            warnings.append(name.upper() + "_UNRESOLVED")
            if name in data and len(unknown) < 50:
                unknown["raw:" + name] = data[name][:500]
        return value

    def address_field(name: str) -> str | None:
        raw = data.get(name)
        try:
            if raw is None or "%" in raw or len(raw) > 64:
                raise ValueError
            return str(ip_address(raw))
        except ValueError:
            warnings.append(name.upper() + "_UNRESOLVED")
            if raw is not None and len(unknown) < 50:
                unknown["raw:" + name] = raw[:500]
            return None

    origin = data.get("FilterOrigin")
    if not origin or origin == "-" or len(origin) > 128:
        origin = None
        warnings.append("FILTER_ORIGIN_UNAVAILABLE")
    result = {
        "event_id": event_id,
        "provider": provider,
        "record_id": record_id,
        "event_version": version,
        "timestamp_utc": timestamp.isoformat(),
        "application_raw": application_raw,
        "application_canonical": canonical,
        "pid_raw": pid_raw,
        "pid_value": pid,
        "direction": direction.value,
        "source_address": address_field("SourceAddress"),
        "source_port": integer_field("SourcePort", 65535),
        "destination_address": address_field("DestAddress"),
        "destination_port": integer_field("DestPort", 65535),
        "protocol": integer_field("Protocol", 255),
        "filter_runtime_id": integer_field("FilterRTID", 2**64 - 1),
        "filter_origin": origin,
        "interface_index": integer_field("InterfaceIndex", 2**32 - 1),
        "source_ref": source_ref,
        "warnings": list(dict.fromkeys(warnings)),
        "unknown_fields": unknown,
    }
    return Event.model_validate_json(json.dumps(result))
