"""Reject deep, duplicate-key and oversized JSON before model validation."""

import json
import math


def checked_json(
    data: bytes,
    *,
    byte_limit: int,
    max_depth: int = 24,
    max_values: int = 500000,
    retain_objects: bool = True,
) -> object:
    if len(data) > byte_limit:
        raise ValueError("JSON byte budget exceeded")
    depth = 0
    quoted = False
    escaped = False
    string_bytes = 0
    values = 0
    primitive = False
    for byte in data:
        if primitive:
            if byte in (9, 10, 13, 32, 44, 93, 125):
                primitive = False
            else:
                continue
        if quoted:
            string_bytes += 1
            if string_bytes > 32768:
                raise ValueError("JSON string budget exceeded")
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
            string_bytes = 0
            values += 1
        elif byte in (123, 91):
            depth += 1
            values += 1
            if depth > max_depth:
                raise ValueError("JSON nesting budget exceeded")
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                raise ValueError("Malformed JSON structure")
        elif byte in b"-0123456789tfn":
            # One lexical token per number/boolean/null. Strings (including keys)
            # and containers also count once. Commas are separators, not values.
            values += 1
            primitive = True
        if values > max_values:
            raise ValueError("JSON value count budget exceeded")
    if quoted or depth != 0:
        raise ValueError("Incomplete JSON structure")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object] | None:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON property")
            result[key] = value
        # Callers that only need a syntax/duplicate/budget check can discard each
        # completed object. Avoid a second full object tree before Pydantic reads it.
        return result if retain_objects else None

    # JSON is UTF8 only. Non-finite numbers are not valid evidence values.
    text = data.decode("utf-8-sig", errors="strict")

    def invalid_constant(value: str) -> object:
        raise ValueError("Non-finite JSON number")

    def bounded_integer(value: str) -> int:
        if len(value.lstrip("-")) > 20:
            raise ValueError("JSON integer budget exceeded")
        return int(value)

    def finite_number(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Non-finite JSON number")
        return result

    result: object = json.loads(
        text,
        object_pairs_hook=unique_object,
        parse_constant=invalid_constant,
        parse_int=bounded_integer,
        parse_float=finite_number,
    )
    return result
