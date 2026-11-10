"""Pure bounded W3C-style text observations, never application identity evidence."""

from collections.abc import Iterable
from datetime import UTC, datetime, timezone
from ipaddress import ip_address

from wfdiag.contracts.models import RejectedTextRecord, TextLogResult, TextObservation

MAX_LOG_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 16384
MAX_LOG_LINES = 100000


def _address(value: str | None) -> str | None:
    if value is None:
        return None
    if "%" in value:
        raise ValueError("unverified_interface")
    return str(ip_address(value))


def _port(value: str | None) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.isdecimal() or len(value) > 5:
        raise ValueError("invalid_port")
    number = int(value)
    if number > 65535:
        raise ValueError("invalid_port")
    return number


def parse_firewall_log(
    lines: Iterable[bytes], *, recorded_offset: timezone | None = None
) -> TextLogResult:
    """Caller supplies bounded physical lines. No file, timezone or host state is read.

    recorded_offset must come from independently recorded capture context, never the
    analyzing computer's timezone. A recorded UTC header is honored; Local stays unknown.
    Fields named path/pid are retained as text and never become application identities.
    """
    observations: list[TextObservation] = []
    rejected: list[RejectedTextRecord] = []
    fields: tuple[str, ...] | None = None
    header_utc = False
    total = 0
    truncated = False
    required = {"date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port"}
    if recorded_offset is not None and not isinstance(recorded_offset, timezone):
        raise ValueError("Only a separately recorded fixed offset is accepted")
    for index, raw in enumerate(lines, start=1):
        reference = f"firewall-log:{index}"
        total += len(raw)
        if index > MAX_LOG_LINES or total > MAX_LOG_BYTES:
            rejected.append(
                RejectedTextRecord(source_ref=reference, reason="input_budget_exceeded")
            )
            truncated = True
            break
        if len(raw) > MAX_LINE_BYTES:
            rejected.append(RejectedTextRecord(source_ref=reference, reason="line_budget_exceeded"))
            truncated = True
            continue
        try:
            line = raw.decode("utf-8-sig" if index == 1 else "utf-8").strip()
        except UnicodeError:
            rejected.append(RejectedTextRecord(source_ref=reference, reason="invalid_encoding"))
            continue
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith(("#Version:", "#Software:")):
                fields = None
                header_utc = False
            elif line.startswith("#Fields:"):
                names = tuple(line.removeprefix("#Fields:").strip().split())
                fields = (
                    names
                    if required.issubset(names)
                    and len(names) == len(set(names))
                    and len(names) <= 64
                    and all(1 <= len(name) <= 128 for name in names)
                    else None
                )
                if fields is None:
                    rejected.append(
                        RejectedTextRecord(source_ref=reference, reason="invalid_fields_header")
                    )
            elif line.startswith("#Time Format:"):
                header_utc = line.removeprefix("#Time Format:").strip() == "UTC"
            continue
        if not raw.endswith((b"\n", b"\r")):
            rejected.append(RejectedTextRecord(source_ref=reference, reason="unterminated_record"))
            truncated = True
            continue
        if fields is None:
            rejected.append(
                RejectedTextRecord(source_ref=reference, reason="missing_fields_header")
            )
            continue
        values = line.split()
        if len(values) != len(fields):
            rejected.append(RejectedTextRecord(source_ref=reference, reason="field_count_mismatch"))
            continue
        row = {
            key: None if value == "-" else value for key, value in zip(fields, values, strict=True)
        }
        try:
            wall = datetime.strptime(f"{row['date']} {row['time']}", "%Y-%m-%d %H:%M:%S")
            offset = UTC if header_utc else recorded_offset
            instant = wall.replace(tzinfo=offset).astimezone(UTC) if offset is not None else None
            source, destination = _address(row["src-ip"]), _address(row["dst-ip"])
            if (
                source
                and destination
                and ip_address(source).version != ip_address(destination).version
            ):
                raise ValueError("mixed_address_family")
            action, protocol = row["action"], row["protocol"]
            if action not in ("DROP", "ALLOW") or protocol not in ("TCP", "UDP", "ICMP", "ICMPV6"):
                raise ValueError("unsupported_record")
            observations.append(
                TextObservation.model_validate(
                    {
                        "source_ref": reference,
                        "timestamp_wall": wall,
                        "timestamp_utc": instant,
                        "time_basis": "recorded_utc"
                        if header_utc
                        else "recorded_offset"
                        if offset
                        else "unknown",
                        "action": action,
                        "protocol": protocol,
                        "source_address": source,
                        "destination_address": destination,
                        "source_port": _port(row["src-port"]),
                        "destination_port": _port(row["dst-port"]),
                        "fields": tuple(row.items()),
                    }
                )
            )
        except (ValueError, OverflowError):
            rejected.append(
                RejectedTextRecord(source_ref=reference, reason="invalid_or_unsupported_record")
            )
    return TextLogResult(
        observations=tuple(observations), rejected=tuple(rejected), truncated=truncated
    )
