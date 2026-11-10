"""Messages mapping with fixed system instruction and structured JSON output."""

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


class AnthropicAdapter:
    def serialize(self, model: Model, request: AiRequest) -> bytes:
        return encode(
            {
                "model": model.model,
                "max_tokens": OUTPUT_LIMIT,
                "stream": False,
                "system": prompt(),
                "messages": [{"role": "user", "content": request.model_dump_json()}],
                "output_config": {"format": {"type": "json_schema", "schema": response_schema()}},
            }
        )

    def parse(self, data: bytes, model: Model) -> tuple[bytes, AiUsage]:
        tree = response_object(data)
        details = tree.get("stop_details")
        if tree.get("stop_reason") == "refusal" or (
            isinstance(details, dict) and details.get("type") == "refusal"
        ):
            raise AiFailure(AiErrorCode.POLICY)
        if (
            tree.get("type") != "message"
            or tree.get("role") != "assistant"
            or tree.get("stop_reason") != "end_turn"
        ):
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        if tree.get("model") != model.model:
            raise AiFailure(AiErrorCode.MODEL_UNAVAILABLE)
        blocks = array_value(tree.get("content"))
        if len(blocks) != 1:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        block = object_value(blocks[0])
        if block.get("type") != "text" or block.get("citations") not in (None, []):
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        return text_value(block.get("text")).encode(), usage(
            tree.get("usage"), "input_tokens", "output_tokens"
        )
