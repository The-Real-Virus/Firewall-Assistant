"""Single-candidate generateContent mapping; no grounding, tools or cached context."""

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


class GeminiAdapter:
    def serialize(self, model: Model, request: AiRequest) -> bytes:
        return encode(
            {
                "systemInstruction": {"parts": [{"text": prompt()}]},
                "contents": [{"role": "user", "parts": [{"text": request.model_dump_json()}]}],
                "generationConfig": {
                    "candidateCount": 1,
                    "maxOutputTokens": OUTPUT_LIMIT,
                    "responseMimeType": "application/json",
                    "responseJsonSchema": response_schema(),
                },
            }
        )

    def parse(self, data: bytes, model: Model) -> tuple[bytes, AiUsage]:
        tree = response_object(data)
        feedback = tree.get("promptFeedback")
        if isinstance(feedback, dict) and feedback.get("blockReason"):
            raise AiFailure(AiErrorCode.POLICY)
        candidates = array_value(tree.get("candidates"))
        if len(candidates) != 1:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        candidate = object_value(candidates[0])
        if candidate.get("finishReason") in (
            "SAFETY",
            "BLOCKLIST",
            "PROHIBITED_CONTENT",
            "SPII",
            "RECITATION",
        ):
            raise AiFailure(AiErrorCode.POLICY)
        if (
            candidate.get("finishReason") != "STOP"
            or candidate.get("citationMetadata")
            or candidate.get("groundingMetadata")
        ):
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        content = object_value(candidate.get("content"))
        if content.get("role") != "model":
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        parts = array_value(content.get("parts"))
        if len(parts) != 1:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        part = object_value(parts[0])
        if set(part) - {"text", "thoughtSignature"}:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        return text_value(part.get("text")).encode(), usage(
            tree.get("usageMetadata"), "promptTokenCount", "candidatesTokenCount"
        )
