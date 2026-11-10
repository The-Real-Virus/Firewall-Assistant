"""Separate AI service. It accepts no engine write handles or collection capability."""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from wfdiag.ai.contracts import (
    AiConfiguration,
    AiErrorCode,
    AiRequest,
    AiUsage,
    Consent,
    Explanation,
    Provider,
    validate_explanation,
)
from wfdiag.ai.credentials import KeyMaterial
from wfdiag.ai.models import Model, selected_model
from wfdiag.ai.policy import (
    AiFailure,
    DisclosurePolicy,
    require_provider_policy,
    validate_content,
    verify_consent,
)
from wfdiag.ai.providers.anthropic import AnthropicAdapter
from wfdiag.ai.providers.base import PROMPT_VERSION, ProviderAdapter
from wfdiag.ai.providers.gemini import GeminiAdapter
from wfdiag.ai.providers.openai import OpenAIAdapter
from wfdiag.ai.usage import Allowance

if TYPE_CHECKING:
    import httpx


def adapter(provider: Provider) -> ProviderAdapter:
    adapters: dict[Provider, ProviderAdapter] = {
        Provider.OPENAI: OpenAIAdapter(),
        Provider.ANTHROPIC: AnthropicAdapter(),
        Provider.GOOGLE: GeminiAdapter(),
    }
    return adapters[provider]


@dataclass(frozen=True, repr=False)
class Prepared:
    configuration: AiConfiguration
    request: AiRequest
    revision: str
    model: Model
    payload: bytes
    policy: DisclosurePolicy
    trusted_synthetic: bool = False
    prompt_version: str = PROMPT_VERSION

    def __repr__(self) -> str:
        return "Prepared(<reviewed AI request>)"


def prepare(
    configuration: AiConfiguration,
    request: AiRequest,
    revision: str,
    policy: DisclosurePolicy,
    *,
    trusted_synthetic: bool = False,
) -> Prepared:
    require_provider_policy(configuration, request, trusted_synthetic=trusted_synthetic)
    assert configuration.provider is not None and configuration.model is not None
    model = selected_model(configuration.provider, configuration.model)
    policy.check_text(request.question, character_limit=1000)
    policy.check_json(request.model_dump_json().encode())
    payload = adapter(model.provider).serialize(model, request)
    policy.check_json(payload)
    return Prepared(configuration, request, revision, model, payload, policy, trusted_synthetic)


@dataclass(frozen=True)
class SendRecord:
    request_id: str
    timestamp_utc: str
    provider: Provider
    model: str
    outcome: str
    seconds: float
    usage: AiUsage = field(default_factory=AiUsage)


class AiSession:
    def __init__(self) -> None:
        self.allowance = Allowance()
        self.records: list[SendRecord] = []

    async def send(
        self,
        prepared: Prepared,
        consent: Consent,
        key: KeyMaterial,
        *,
        _test_transport: "httpx.AsyncBaseTransport | None" = None,
    ) -> tuple[Explanation, AiUsage]:
        # Rebuild before charging the allowance or constructing a client. This detects
        # mutated resources, forged prepared bodies and changed provider/prompt/schema.
        current = prepare(
            prepared.configuration,
            prepared.request,
            prepared.revision,
            prepared.policy,
            trusted_synthetic=prepared.trusted_synthetic,
        )
        if (
            current.payload != prepared.payload
            or current.model != prepared.model
            or current.prompt_version != prepared.prompt_version
        ):
            raise AiFailure(AiErrorCode.STALE_CONSENT)
        verify_consent(
            consent,
            provider=current.model.provider,
            model=current.model.model,
            payload=current.payload,
            revision=current.revision,
            prompt_version=current.prompt_version,
        )
        # Prevent an arbitrary locally entered key from being repeated in question data.
        DisclosurePolicy((key.reveal_for_request(),)).check_json(current.payload)
        self.allowance.begin()
        start = time.monotonic()
        usage = AiUsage()
        outcome = AiErrorCode.PROVIDER_FAILURE.value
        try:
            from wfdiag.ai.transport import post

            raw = await post(current.model, current.payload, key, _test_transport=_test_transport)
            data, usage = adapter(current.model.provider).parse(raw, current.model)
            try:
                explanation = validate_explanation(data, current.request)
            except (ValueError, UnicodeError):
                raise AiFailure(AiErrorCode.RESPONSE_INVALID) from None
            validate_content(explanation, current.policy)
            validate_content(explanation, DisclosurePolicy((key.reveal_for_request(),)))
            outcome = explanation.status
            return explanation, usage
        except asyncio.CancelledError:
            outcome = AiErrorCode.CANCELLED.value
            raise AiFailure(AiErrorCode.CANCELLED) from None
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
                    current.model.provider,
                    current.model.model,
                    outcome,
                    round(time.monotonic() - start, 3),
                    usage,
                )
            )
            del self.records[:-200]
