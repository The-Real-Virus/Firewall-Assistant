"""Conversational action dispatch over real bounded transport and invented provider replies."""

import asyncio
import json

import httpx
import pytest
from pydantic import ValidationError

from wfdiag.ai.assistant import AppAction, AssistantSession, ChatPrivacy, serialize
from wfdiag.ai.contracts import AiErrorCode, Provider
from wfdiag.ai.credentials import KeyMaterial
from wfdiag.ai.models import CHAT_MODELS as MODELS
from wfdiag.ai.policy import AiFailure


def response(provider, model, message, actions=()):
    text = json.dumps({"message": message, "actions": list(actions)})
    if provider == Provider.GOOGLE:
        return {
            "candidates": [
                {"finishReason": "STOP", "content": {"role": "model", "parts": [{"text": text}]}}
            ]
        }
    if provider == Provider.ANTHROPIC:
        return {
            "type": "message",
            "role": "assistant",
            "model": model,
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": text}],
        }
    return {
        "status": "completed",
        "model": model,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text}],
            }
        ],
    }


class Stream(httpx.AsyncByteStream):
    def __init__(self, value):
        self.value = json.dumps(value).encode()

    async def __aiter__(self):
        yield self.value


@pytest.mark.parametrize("model", MODELS)
def test_chat_remembers_followup_and_executes_only_validated_application_action(model) -> None:
    seen = []
    called = []
    key = KeyMaterial("invented-session-key")
    action = AppAction(name="open_example").model_dump(mode="json")

    def handler(request):
        payload = request.content
        assert b"invented-session-key" not in payload and b"192.168.56.20" not in payload
        seen.append(payload)
        n = len(seen)
        body = response(
            model.provider,
            model.model,
            "Connected"
            if n == 1
            else "I'll open the example."
            if n == 2
            else "The example is open.",
            [action] if n == 2 else [],
        )
        return httpx.Response(
            200, headers={"content-type": "application/json"}, stream=Stream(body)
        )

    async def execute(value):
        called.append(value.name)
        return {"status": "completed", "case_loaded": True}

    async def run():
        session = AssistantSession()
        transport = httpx.MockTransport(handler)
        assert await session.connect(model, key, _test_transport=transport) == "connected"
        message, _ = await session.chat(
            model,
            key,
            "Open an example for192.168.56.20",
            {},
            ChatPrivacy((key.reveal_for_request(),)),
            execute,
            lambda value: None,
            _test_transport=transport,
        )
        assert message == "The example is open." and called == ["open_example"]
        await session.chat(
            model,
            key,
            "What does it mean?",
            {},
            ChatPrivacy(),
            execute,
            lambda value: None,
            _test_transport=transport,
        )
        assert len(session.history) == 4
        assert b"The example is open." in seen[-1]
        assert session.allowance.attempts == 4

    asyncio.run(run())


@pytest.mark.parametrize("name", ["shell", "change_firewall", "read_credentials", "upload_files"])
def test_arbitrary_computer_tools_cannot_enter_app_dispatcher(name) -> None:
    with pytest.raises(ValidationError):
        AppAction.model_validate_json(json.dumps({"name": name}))


def test_chat_redacts_local_values_instead_of_forcing_user_to_remove_every_identifier() -> None:
    policy = ChatPrivacy(("PrivateApp.exe", "invented-session-key"))
    value = policy.redact("Why does PrivateApp.exe fail at192.168.56.20? invented-session-key")
    assert "PrivateApp.exe" not in value and "192.168.56.20" not in value
    assert "invented-session-key" not in value and "Why does" in value


@pytest.mark.parametrize(
    "value",
    [
        r"Help with C:\Users\Alice\Program Files\PrivateApp.exe",
        r"Help with \\private-server\Alice\data.txt",
        "Explain https://private.example/account?token=HiddenToken",
        "Authorization: Bearer HiddenToken",
    ],
)
def test_unknown_pasted_paths_links_and_bearer_tokens_are_hidden_completely(value):
    safe = ChatPrivacy().redact(value)
    for private in ("Alice", "PrivateApp", "private-server", "private.example", "HiddenToken"):
        assert private not in safe


def test_case_identity_index_refuses_incrementally_before_reading_every_large_case_page():
    visited = []

    def values():
        for index in range(100000):
            visited.append(index)
            yield f"private-value-{index}"

    with pytest.raises(AiFailure) as error:
        ChatPrivacy(values())
    assert error.value.code == AiErrorCode.DISCLOSURE and len(visited) < 20000


@pytest.mark.parametrize("model", MODELS)
def test_assistant_requests_use_documented_portable_provider_schema(model):
    payload = json.loads(serialize(model, {"connection_test": True}))
    if model.provider == Provider.GOOGLE:
        config = payload["generationConfig"]
        assert "candidateCount" not in config
        assert config["thinkingConfig"]["thinkingLevel"] == (
            "MINIMAL" if model.model.endswith("flash-lite") else "LOW"
        )
        assert "maxOutputTokens" not in config
        schema = config["responseJsonSchema"]
    elif model.provider == Provider.ANTHROPIC:
        assert payload["max_tokens"] == 64000
        schema = payload["output_config"]["format"]["schema"]
    else:
        assert "max_output_tokens" not in payload
        schema = payload["text"]["format"]["schema"]
    wire = json.dumps(schema)
    assert '"minimum"' not in wire and '"maximum"' not in wire
    for invalid in (0, 61):
        with pytest.raises(ValidationError):
            AppAction(name="collect_evidence", minutes=invalid)
