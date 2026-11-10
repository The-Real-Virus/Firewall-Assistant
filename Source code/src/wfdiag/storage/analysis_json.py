"""Bounded incremental persistence of validated analysis; no loss of evidence or schema meaning."""

import json
from collections.abc import Callable, Iterator

from wfdiag.contracts.base import Contract
from wfdiag.contracts.models import Analysis, Finding, TextLogResult
from wfdiag.services.cancellation import CancellationToken


def analysis_json_chunks(
    analysis: Analysis,
    cancellation: CancellationToken | None = None,
    *,
    include_metadata_defaults: bool = False,
) -> Iterator[bytes]:
    token = cancellation or CancellationToken()
    token.check()
    # Defaults reconstruct identically through the existing schema. Never omit null
    # required fields, false eligibility, uncertainty, or provenance. Per-finding
    # serialization avoids a complete JSON string plus UTF8 copy in peak memory.
    header = analysis.model_dump_json(
        exclude={"findings", "policy_rules", "firewall_log"},
        exclude_defaults=not include_metadata_defaults,
    ).encode("utf-8")
    yield header[:-1]
    if analysis.firewall_log is not None:
        yield b',"firewall_log":'
        yield from text_log_json_chunks(analysis.firewall_log, token)
    elif include_metadata_defaults:
        yield b',"firewall_log":null'
    if analysis.policy_rules is not None:
        yield b',"policy_rules":['
        for index, rule in enumerate(analysis.policy_rules):
            token.check()
            if index:
                yield b","
            yield rule.model_dump_json(exclude_defaults=True).encode("utf-8")
        yield b"]"
    elif include_metadata_defaults:
        yield b',"policy_rules":null'
    yield b',"findings":['
    for index, finding in enumerate(analysis.findings):
        token.check()
        if index:
            yield b","
        yield finding.model_dump_json(exclude_defaults=True).encode("utf-8")
    token.check()
    yield b"]}\n"


def text_log_json_chunks(
    log: TextLogResult, cancellation: CancellationToken | None = None
) -> Iterator[bytes]:
    token = cancellation or CancellationToken()
    token.check()
    yield log.model_dump_json(exclude={"observations", "rejected"}).encode("utf-8")[:-1]
    for name, records in (("observations", log.observations), ("rejected", log.rejected)):
        yield (',"' + name + '":[').encode("utf-8")
        for index, record in enumerate(records):
            token.check()
            if index:
                yield b","
            yield record.model_dump_json().encode("utf-8")
        yield b"]"
    token.check()
    yield b"}"


def analysis_data_from_checked_json(
    text: str,
    *,
    finding_consumer: Callable[[Finding, int, int], None] | None = None,
    retain_findings: bool = True,
) -> dict[str, object]:
    return model_array_data_from_checked_json(
        text,
        Analysis,
        Finding,
        maximum_items=100002,
        item_consumer=finding_consumer,
        retain_items=retain_findings,
    )


def model_array_data_from_checked_json[Parent: Contract, Item: Contract](
    text: str,
    model: type[Parent],
    item_model: type[Item],
    *,
    maximum_items: int,
    item_consumer: Callable[[Item, int, int], None] | None = None,
    retain_items: bool = True,
    metadata_character_limit: int | None = None,
    item_character_limit: int | None = None,
) -> dict[str, object]:
    """Decode after checked_json's full syntax, duplicate and budget validation.

    A complete Pydantic JSON parse keeps its temporary tree alongside100000 models.
    Decode one finding at a time, then run the unchanged complete Analysis validator.
    Never use this helper as a replacement for the storage precheck/file identity checks.
    """
    decoder = json.JSONDecoder()

    def decode_at(position: int, limit: int | None) -> tuple[object, int]:
        if limit is None:
            return decoder.raw_decode(text, position)
        if limit <= 0:
            raise ValueError("Record metadata or item exceeds its character budget")
        value, end = decoder.raw_decode(text[position : position + limit + 1])
        if end > limit:
            raise ValueError("Record metadata or item exceeds its character budget")
        return value, position + end

    metadata_used = 2

    def metadata_remaining() -> int | None:
        return (
            None if metadata_character_limit is None else metadata_character_limit - metadata_used
        )

    def whitespace(position: int) -> int:
        while position < len(text) and text[position] in " \t\r\n":
            position += 1
        return position

    cursor = whitespace(0)
    if cursor >= len(text) or text[cursor] != "{":
        raise ValueError("An analysis object is required")
    cursor = whitespace(cursor + 1)
    header_fields = []
    findings: list[Item] = []
    count = 0
    while cursor < len(text) and text[cursor] != "}":
        name, cursor = decode_at(cursor, metadata_remaining())
        # checked_json already validated object grammar, so keys are JSON strings.
        cursor = whitespace(cursor)
        if text[cursor] != ":":
            raise ValueError("Invalid analysis property")
        cursor = whitespace(cursor + 1)
        if name == "findings":
            if text[cursor] != "[":
                raise ValueError("Findings must be an array")
            cursor = whitespace(cursor + 1)
            while text[cursor] != "]":
                start = cursor
                ignored, cursor = decode_at(cursor, item_character_limit)
                del ignored
                finding = item_model.model_validate_json(text[start:cursor])
                count += 1
                if count > maximum_items:
                    raise ValueError("Analysis finding count exceeds the schema limit")
                if item_consumer is not None:
                    item_consumer(finding, start, cursor)
                if retain_items:
                    findings.append(finding)
                cursor = whitespace(cursor)
                if text[cursor] == ",":
                    cursor = whitespace(cursor + 1)
                elif text[cursor] != "]":
                    raise ValueError("Invalid findings array")
            cursor += 1
            field = '"findings":[]'
        else:
            start = cursor
            ignored, cursor = decode_at(cursor, metadata_remaining())
            del ignored
            field = json.dumps(name) + ":" + text[start:cursor]
        metadata_used += len(field) + 1
        if metadata_character_limit is not None and metadata_used > metadata_character_limit:
            raise ValueError("Record metadata exceeds its character budget")
        header_fields.append(field)
        cursor = whitespace(cursor)
        if text[cursor] == ",":
            cursor = whitespace(cursor + 1)
        elif text[cursor] != "}":
            raise ValueError("Invalid analysis object")
    if cursor >= len(text) or text[cursor] != "}" or whitespace(cursor + 1) != len(text):
        raise ValueError("Invalid or trailing analysis data")
    header = model.model_validate_json("{" + ",".join(header_fields) + "}")
    return {
        **{name: getattr(header, name) for name in model.model_fields},
        "findings": tuple(findings),
    }
