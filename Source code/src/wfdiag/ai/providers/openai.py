"""Stateless Responses mapping; no tools or remote response state."""

from wfdiag.ai.contracts import AiErrorCode, AiRequest, AiUsage
from wfdiag.ai.models import Model
from wfdiag.ai.policy import AiFailure
from wfdiag.ai.providers.base import (
    OUTPUT_LIMIT,
    array_value,
    encode,
    object_value,
    prompt,
    response_object,
    response_schema,
    text_value,
    usage,
)


class OpenAIAdapter:
    def serialize(self, model: Model, request: AiRequest) -> bytes:
        return encode(
            {
                "model": model.model,
                "store": False,
                "stream": False,
                "max_output_tokens": OUTPUT_LIMIT,
                "reasoning": {"effort": "none"},
                "input": [
                    {"role": "system", "content": prompt()},
                    {"role": "user", "content": request.model_dump_json()},
                ],
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "wfdiag_explanation_v1",
                        "strict": True,
                        "schema": response_schema(),
                    }
                },
            }
        )

    def parse(self, data: bytes, model: Model) -> tuple[bytes, AiUsage]:
        tree = response_object(data)
        if (
            tree.get("error") is not None
            or tree.get("status") != "completed"
            or tree.get("incomplete_details") is not None
        ):
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        if tree.get("model") != model.model:
            raise AiFailure(AiErrorCode.MODEL_UNAVAILABLE)
        output = array_value(tree.get("output"))
        if len(output) != 1:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        message = object_value(output[0])
        if (
            message.get("type") != "message"
            or message.get("role") != "assistant"
            or message.get("status") != "completed"
        ):
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        blocks = array_value(message.get("content"))
        if len(blocks) != 1:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        block = object_value(blocks[0])
        if block.get("type") == "refusal":
            raise AiFailure(AiErrorCode.POLICY)
        if block.get("type") != "output_text" or block.get("annotations") not in (None, []):
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        return text_value(block.get("text")).encode(), usage(
            tree.get("usage"), "input_tokens", "output_tokens"
        )
