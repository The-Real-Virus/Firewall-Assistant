"""Conversational application assistant with bounded, locally dispatched actions."""

import hashlib
import json
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime
from importlib.resources import files
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, model_validator

from wfdiag.ai.contracts import AiErrorCode, AiUsage, Provider, PublicReference
from wfdiag.ai.credentials import KeyMaterial
from wfdiag.ai.models import Model
from wfdiag.ai.policy import (
    MAX_POLICY_CHARACTERS,
    MAX_POLICY_VALUES,
    SENSITIVE,
    AiFailure,
    DisclosurePolicy,
    normalized,
)
from wfdiag.ai.providers.base import encode
from wfdiag.ai.service import AiSession, SendRecord, adapter
from wfdiag.ai.usage import Allowance
from wfdiag.contracts.base import Contract
from wfdiag.storage.json_input import checked_json

if TYPE_CHECKING:
    import httpx

ActionName = Literal[
    "get_app_state",
    "navigate",
    "open_example",
    "choose_case",
    "run_preflight",
    "collect_evidence",
    "analyze_case",
    "read_findings",
    "select_finding",
    "export_report",
    "prepare_proposal",
    "compare_cases",
]
Screen = Literal["Overview", "Diagnose", "Cases", "Compare", "Settings", "AI Assistant"]


class AppAction(Contract):
    name: ActionName
    screen: Screen | None = None
    minutes: Annotated[int, Field(ge=1, le=60)] | None = None
    finding_ref: PublicReference | None = None
    report_mode: Literal["share", "full"] | None = None
    page: Annotated[int, Field(ge=1, le=5000)] | None = None

    @model_validator(mode="after")
    def arguments_match_action(self) -> "AppAction":
        allowed = {
            "navigate": {"screen"},
            "collect_evidence": {"minutes"},
            "select_finding": {"finding_ref"},
            "export_report": {"report_mode"},
            "read_findings": {"page"},
        }.get(self.name, set())
        for name in ("screen", "minutes", "finding_ref", "report_mode", "page"):
            if name not in allowed and getattr(self, name) is not None:
                raise ValueError("Argument does not belong to this application action")
        if self.name == "navigate" and self.screen is None:
            raise ValueError("Choose an application screen")
        if self.name == "select_finding" and self.finding_ref is None:
            raise ValueError("Choose a current finding reference")
        return self


class AssistantReply(Contract):
    message: Annotated[str, Field(min_length=1, max_length=131072)]
    actions: Annotated[tuple[AppAction, ...], Field(max_length=3)]


class ChatPrivacy:
    """Replace local values before sending; never serialize this identity index."""

    def __init__(self, forbidden: Iterable[str] = ()) -> None:
        values: set[str] = set()
        characters = 0
        for value in forbidden:
            value = normalized(value)
            if not value or value in values:
                continue
            characters += len(value)
            if len(values) >= MAX_POLICY_VALUES or characters > MAX_POLICY_CHARACTERS:
                raise AiFailure(AiErrorCode.DISCLOSURE)
            values.add(value)
        self.values = tuple(sorted(values, key=len, reverse=True))
        self.policy = DisclosurePolicy(self.values)

    def redact(self, text: str) -> str:
        if len(text) > 65536:
            raise AiFailure(AiErrorCode.DISCLOSURE)
        result = normalized(text)
        for value in self.values:
            pattern = re.escape(value)
            if len(value) < 6:
                pattern = r"(?<!\w)" + pattern + r"(?!\w)"
            result = re.sub(pattern, "[private]", result, flags=re.IGNORECASE)
        result = re.sub(
            r"\b(?:api[_-]?key|authorization)\s*[:=]\s*(?:Bearer\s+)?\S+|\bBearer\s+\S+",
            "[secret removed]",
            result,
            flags=re.IGNORECASE,
        )
        # Addresses can be pasted adjacent to prose ("at192..."); word boundaries
        # alone would miss them. Over-redacting numeric examples is preferable.
        result = re.sub(
            r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\d)",
            "[private address]",
            result,
        )
        result = re.sub(
            r"(?:[A-Za-z][A-Za-z0-9+.-]{1,20}://|www\.)[^\s<>\"']+",
            "[private link]",
            result,
            flags=re.IGNORECASE,
        )
        # Unquoted Windows paths can contain spaces. Conservatively hide the
        # rest of that line, rather than sending the user's folder/account names.
        result = re.sub(
            r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\)[^\r\n]*",
            "[private path]",
            result,
        )
        result = SENSITIVE.sub("[private]", result)
        self.policy.check_text(result)
        return result

    def __repr__(self) -> str:
        return "ChatPrivacy(<private identity index>)"


def reply_schema() -> dict[str, object]:
    action = AppAction.model_json_schema()
    # Provider strict output requires every property, including nullable arguments.
    action["required"] = list(action["properties"])
    action.pop("title", None)
    for value in action["properties"].values():
        value.pop("default", None)
        value.pop("title", None)
        # Claude's raw JSON schema API rejects numeric limits. Keep the wire
        # schema portable; AppAction still enforces every limit before dispatch.
        for variant in value.get("anyOf", []):
            variant.pop("minimum", None)
            variant.pop("maximum", None)
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "message": {"type": "string"},
            "actions": {"type": "array", "items": action},
        },
        "required": ["message", "actions"],
    }


def serialize(model: Model, envelope: dict[str, object]) -> bytes:
    prompt = files("wfdiag").joinpath("resources/ai/assistant-v2.txt").read_text("utf-8")
    content = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    schema = reply_schema()
    if envelope.get("connection_test"):
        # A key check does not need the full application/action grammar. Avoid
        # compiling a large tool schema just to obtain a synthetic greeting.
        prompt = 'Return JSON with message "Connected" and actions []. This is a connection test, with no application actions.'
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "message": {"type": "string"},
                "actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["message", "actions"],
        }
    if model.provider == Provider.OPENAI:
        return encode(
            {
                "model": model.model,
                "store": False,
                "stream": False,
                "reasoning": {"effort": "none"},
                "input": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": content},
                ],
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "wfdiag_assistant_v2",
                        "strict": True,
                        "schema": schema,
                    }
                },
            }
        )
    if model.provider == Provider.ANTHROPIC:
        return encode(
            {
                "model": model.model,
                # Messages requires this field; use the model's published maximum.
                "max_tokens": 64000,
                "stream": False,
                "system": prompt,
                "messages": [{"role": "user", "content": content}],
                "output_config": {"format": {"type": "json_schema", "schema": schema}},
            }
        )
    return encode(
        {
            "systemInstruction": {"parts": [{"text": prompt}]},
            "contents": [{"role": "user", "parts": [{"text": content}]}],
            "generationConfig": {
                # Let the provider choose its model default output allowance.
                "thinkingConfig": {
                    "thinkingLevel": "MINIMAL" if model.model.endswith("flash-lite") else "LOW",
                    "includeThoughts": False,
                },
                "responseMimeType": "application/json",
                "responseJsonSchema": schema,
            },
        }
    )


Execute = Callable[[AppAction], Awaitable[dict[str, object]]]
Progress = Callable[[str], None]


class AssistantSession(AiSession):
    def __init__(self) -> None:
        super().__init__()
        self.allowance = Allowance()
        self.history: list[dict[str, str]] = []
        self.connection: tuple[Provider, str, str] | None = None
        self.last_preview = b""

    @staticmethod
    def identity(model: Model, key: KeyMaterial) -> tuple[Provider, str, str]:
        return (
            model.provider,
            model.model,
            hashlib.sha256(key.reveal_for_request().encode()).hexdigest(),
        )

    def clear(self) -> None:
        self.history.clear()
        self.connection = None
        self.last_preview = b""

    async def request(
        self,
        model: Model,
        key: KeyMaterial,
        envelope: dict[str, object],
        privacy: ChatPrivacy,
        *,
        _test_transport: "httpx.AsyncBaseTransport | None" = None,
    ) -> tuple[AssistantReply, AiUsage]:
        from wfdiag.ai.transport import post

        payload = serialize(model, envelope)
        if len(payload) > 64 * 1024:
            raise AiFailure(AiErrorCode.DISCLOSURE)
        privacy.policy.check_json(payload)
        DisclosurePolicy((key.reveal_for_request(),)).check_json(payload)
        self.last_preview = payload
        self.allowance.begin()
        started, outcome, usage = time.monotonic(), AiErrorCode.PROVIDER_FAILURE.value, AiUsage()
        try:
            # Transport remains provider/host bound, TLS verified, no retries/proxies.
            raw = await post(model, payload, key, _test_transport=_test_transport)
            data, usage = adapter(model.provider).parse(raw, model)
            checked_json(data, byte_limit=256 * 1024, max_depth=12, max_values=2048)
            reply = AssistantReply.model_validate_json(data)
            message = privacy.redact(reply.message)
            reply = reply.model_copy(update={"message": message})
            outcome = "completed"
            return reply, usage
        except AiFailure as error:
            outcome = error.code.value
            raise
        except (ValueError, UnicodeError, TypeError):
            outcome = AiErrorCode.RESPONSE_INVALID.value
            raise AiFailure(AiErrorCode.RESPONSE_INVALID) from None
        finally:
            self.allowance.finish()
            self.records.append(
                SendRecord(
                    str(uuid.uuid4()),
                    datetime.now(UTC).isoformat(),
                    model.provider,
                    model.model,
                    outcome,
                    round(time.monotonic() - started, 3),
                    usage,
                )
            )
            del self.records[:-200]

    async def connect(
        self,
        model: Model,
        key: KeyMaterial,
        *,
        _test_transport: "httpx.AsyncBaseTransport | None" = None,
    ) -> str:
        self.connection = None
        privacy = ChatPrivacy((key.reveal_for_request(),))
        reply, _ = await self.request(
            model,
            key,
            {
                "question": "Connection test: say Connected in one short sentence. Do not request actions.",
                "history": [],
                "application": {},
                "tool_results": [],
                "connection_test": True,
            },
            privacy,
            _test_transport=_test_transport,
        )
        if reply.actions:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
        self.connection = self.identity(model, key)
        return "connected"

    async def chat(
        self,
        model: Model,
        key: KeyMaterial,
        question: str,
        application: dict[str, object],
        privacy: ChatPrivacy,
        execute: Execute,
        progress: Progress,
        *,
        _test_transport: "httpx.AsyncBaseTransport | None" = None,
    ) -> tuple[str, AiUsage]:
        if self.connection != self.identity(model, key):
            raise AiFailure(AiErrorCode.CONFIGURATION)
        if not question.strip() or len(question) > 4000:
            raise AiFailure(AiErrorCode.CONFIGURATION)
        safe_question = privacy.redact(question)
        results: list[dict[str, object]] = []
        executed: set[str] = set()
        usage = AiUsage()
        message = "The shown actions are complete. Ask a follow-up to continue."
        for round_index in range(3):
            progress("Thinking…")
            reply, usage = await self.request(
                model,
                key,
                {
                    "question": safe_question,
                    "history": list(self.history),
                    "application": application,
                    "tool_results": results,
                    "connection_test": False,
                },
                privacy,
                _test_transport=_test_transport,
            )
            message = reply.message
            if not reply.actions:
                break
            for action in reply.actions:
                if len(results) >= 6:
                    message = "I reached this message's action limit. The results above show what completed."
                    break
                signature = (
                    action.name
                    if action.name
                    in ("collect_evidence", "analyze_case", "run_preflight", "choose_case")
                    else action.model_dump_json()
                )
                if signature in executed:
                    results.append({"action": action.name, "status": "already_attempted"})
                    continue
                executed.add(signature)
                progress(action.name.replace("_", " ").capitalize() + "…")
                result = await execute(action)
                privacy.policy.check_json(encode(result))
                results.append({"action": action.name, "result": result})
            else:
                if round_index == 2:
                    message = "I reached this message's action limit. Review the application action results above, then ask a follow-up to continue."
                continue
            break
        self.history.extend(
            [{"role": "user", "text": safe_question}, {"role": "assistant", "text": message}]
        )
        while len(self.history) > 10 or len(encode(self.history)) > 16384:
            del self.history[:2]
        return message, usage
