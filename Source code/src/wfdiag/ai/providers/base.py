"""Provider-independent static schema and strict response primitives."""

import json
from importlib.resources import files
from typing import Protocol

from wfdiag.ai.contracts import AiErrorCode, AiRequest, AiUsage
from wfdiag.ai.models import Model
from wfdiag.ai.policy import AiFailure
from wfdiag.contracts.enums import NextStep
from wfdiag.storage.json_input import checked_json

PROMPT_VERSION = "system-v1"
OUTPUT_LIMIT = 1024
RESPONSE_LIMIT = 256 * 1024


def encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def prompt() -> str:
    return files("wfdiag").joinpath("resources/ai/system-v1.txt").read_text(encoding="utf-8")


def response_schema() -> dict[str, object]:
    # Common provider subset; full bounds/references are enforced locally.
    # Cached schema metadata contains no question, aliases or other case data.
    properties: dict[str, object] = {
        "schema_version": {"type": "string", "enum": ["1.0"]},
        "status": {"type": "string", "enum": ["answered", "insufficient_context", "refused"]},
        "explanation": {"type": "string"},
        "finding_refs": {"type": "array", "items": {"type": "string"}},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "next_step_ids": {
            "type": "array",
            "items": {"type": "string", "enum": [step.value for step in NextStep]},
        },
        "limitations": {"type": "array", "items": {"type": "string"}},
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def object_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise AiFailure(AiErrorCode.RESPONSE_INVALID)
    return value


def array_value(value: object) -> list[object]:
    if not isinstance(value, list):
        raise AiFailure(AiErrorCode.RESPONSE_INVALID)
    return value


def text_value(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AiFailure(AiErrorCode.RESPONSE_INVALID)
    return value


def response_object(data: bytes) -> dict[str, object]:
    try:
        return object_value(
            checked_json(data, byte_limit=RESPONSE_LIMIT, max_depth=20, max_values=20000)
        )
    except (ValueError, UnicodeError):
        raise AiFailure(AiErrorCode.RESPONSE_INVALID) from None


def tokens(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise AiFailure(AiErrorCode.RESPONSE_INVALID)
    return value


def usage(value: object, input_name: str, output_name: str) -> AiUsage:
    tree = {} if value is None else object_value(value)
    output = tokens(tree.get(output_name))
    if output is not None and output >= OUTPUT_LIMIT:
        raise AiFailure(AiErrorCode.RESPONSE_INVALID)
    return AiUsage(input_tokens=tokens(tree.get(input_name)), output_tokens=output)


class ProviderAdapter(Protocol):
    def serialize(self, model: Model, request: AiRequest) -> bytes: ...

    def parse(self, data: bytes, model: Model) -> tuple[bytes, AiUsage]: ...
