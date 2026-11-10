"""Reviewed local candidate list. Documentation review is not live certification."""

from dataclasses import dataclass

from wfdiag.ai.contracts import AiErrorCode, Provider
from wfdiag.ai.policy import AiFailure


@dataclass(frozen=True)
class Model:
    provider: Provider
    model: str
    host: str
    route: str
    output_parameter: str
    api_version: str
    live_verified: bool = False
    review_date: str = "2026-11-03"


MODELS = (
    Model(
        Provider.OPENAI,
        "gpt-5.4-mini-2026-03-17",
        "api.openai.com",
        "/v1/responses",
        "max_output_tokens",
        "v1",
    ),
    Model(
        Provider.ANTHROPIC,
        "claude-haiku-4-5-20251001",
        "api.anthropic.com",
        "/v1/messages",
        "max_tokens",
        "2023-06-01",
    ),
    Model(
        Provider.GOOGLE,
        "gemini-3.8-flash",
        "generativelanguage.googleapis.com",
        "/v1beta/models/gemini-3.8-flash:generateContent",
        "maxOutputTokens",
        "v1beta",
    ),
)

# The explanation-v1 catalog keeps its original three exact models. The current
# chat also offers the reviewed low-latency model without silently falling back.
CHAT_MODELS = (
    *MODELS,
    Model(
        Provider.GOOGLE,
        "gemini-3.5-flash-lite",
        "generativelanguage.googleapis.com",
        "/v1beta/models/gemini-3.5-flash-lite:generateContent",
        "maxOutputTokens",
        "v1beta",
        review_date="2026-11-07",
    ),
)


def selected_model(provider: Provider, model: str) -> Model:
    for item in CHAT_MODELS:
        if item.provider == provider and item.model == model:
            return item
    raise AiFailure(AiErrorCode.MODEL_UNAVAILABLE)
