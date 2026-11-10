"""Invented provider replies only; no provider connection or real key is used."""

import asyncio
import copy
import json
from dataclasses import replace
from importlib.resources import files

import httpx
import pytest

from wfdiag.ai.context import general_request
from wfdiag.ai.contracts import AiConfiguration, AiErrorCode, Provider, validate_explanation
from wfdiag.ai.credentials import KeyMaterial
from wfdiag.ai.models import MODELS, Model, selected_model
from wfdiag.ai.policy import AiFailure, DisclosurePolicy, consent_for, context_revision
from wfdiag.ai.providers.base import encode, response_schema
from wfdiag.ai.service import AiSession, adapter, prepare


def answer() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "status": "answered",
        "explanation": "A firewall profile groups the settings used for a network category.",
        "finding_refs": [],
        "evidence_refs": [],
        "next_step_ids": [],
        "limitations": ["This is general help and makes no statement about this computer."],
    }


def response(value: object) -> httpx.Response:
    return httpx.Response(
        200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(encode(value))
    )


def reply(model: Model, explanation: dict[str, object] | None = None) -> dict[str, object]:
    text = json.dumps(answer() if explanation is None else explanation)
    if model.provider == Provider.OPENAI:
        return {
            "model": model.model,
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": text, "annotations": []}],
                }
            ],
            "usage": {"input_tokens": 200, "output_tokens": 40},
        }
    if model.provider == Provider.ANTHROPIC:
        return {
            "model": model.model,
            "type": "message",
            "role": "assistant",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 200, "output_tokens": 40},
        }
    return {
        "candidates": [
            {"finishReason": "STOP", "content": {"role": "model", "parts": [{"text": text}]}}
        ],
        "usageMetadata": {"promptTokenCount": 200, "candidatesTokenCount": 40},
    }


def reviewed(model: Model):
    request = general_request("profiles")
    prepared = prepare(
        AiConfiguration(enabled=True, provider=model.provider, model=model.model),
        request,
        context_revision("general-help"),
        DisclosurePolicy(),
    )
    consent = consent_for(
        provider=model.provider,
        model=model.model,
        payload=prepared.payload,
        revision=prepared.revision,
        prompt_version=prepared.prompt_version,
    )
    return prepared, consent


@pytest.mark.parametrize("model", MODELS)
def test_stateless_serialization_fixed_schema_and_exact_routing(model: Model) -> None:
    prepared, consent = reviewed(model)
    envelope = json.loads(prepared.payload)
    assert len(prepared.payload) < 64 * 1024
    assert (
        json.loads(adapter(model.provider).serialize(model, general_request("auditing")))
        != envelope
    )
    assert json.dumps(response_schema()) == json.dumps(response_schema())
    assert "What is a firewall profile?" not in json.dumps(response_schema())
    assert not any(
        key in envelope
        for key in ("tools", "previous_response_id", "conversation", "cachedContent", "attachments")
    )
    if model.provider == Provider.OPENAI:
        assert envelope["store"] is False
        assert envelope["max_output_tokens"] == 1024
        assert envelope["text"]["format"]["strict"] is True
    elif model.provider == Provider.ANTHROPIC:
        assert envelope["max_tokens"] == 1024
        assert envelope["output_config"]["format"]["type"] == "json_schema"
    else:
        assert envelope["generationConfig"]["maxOutputTokens"] == 1024
        assert envelope["generationConfig"]["candidateCount"] == 1
    seen = []
    key = "test-fixture-credential-not-real"

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url == f"https://{model.host}{model.route}"
        assert request.method == "POST" and request.content == prepared.payload
        assert key not in str(request.url) and key.encode() not in request.content
        supplied = {
            h for h in ("authorization", "x-api-key", "x-goog-api-key") if h in request.headers
        }
        expected = {
            Provider.OPENAI: "authorization",
            Provider.ANTHROPIC: "x-api-key",
            Provider.GOOGLE: "x-goog-api-key",
        }[model.provider]
        assert supplied == {expected}
        assert request.headers[expected].endswith(key)
        return response(reply(model))

    session = AiSession()
    result, usage = asyncio.run(
        session.send(
            prepared, consent, KeyMaterial(key), _test_transport=httpx.MockTransport(handler)
        )
    )
    assert result.explanation == answer()["explanation"] and usage.output_tokens == 40
    assert usage.estimated_cost is None and usage.billing_confirmed is False
    assert session.allowance.attempts == len(seen) == 1
    assert key not in repr(session.records) + repr(prepared) + repr(KeyMaterial(key))


@pytest.mark.parametrize("model", MODELS)
@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "unknown_ref",
        "wrong_version",
        "too_long",
        "directive",
        "canary",
        "unknown_next_step",
    ],
)
def test_untrusted_explanations_never_become_engine_output(model: Model, change: str) -> None:
    prepared, consent = reviewed(model)
    value = answer()
    if change == "extra":
        value["new_engine_finding"] = "secure"
    elif change == "unknown_ref":
        value["evidence_refs"] = ["EDEADBEEF12345678"]
    elif change == "wrong_version":
        value["schema_version"] = "2.0"
    elif change == "too_long":
        value["explanation"] = "x" * 4001
    elif change == "directive":
        value["explanation"] = "Run New-NetFirewallRule to fix the problem."
    elif change == "canary":
        value["explanation"] = "CANARY_PROVIDER_REPLY"
    else:
        value["next_step_ids"] = ["RUN_COMMAND"]
    before = prepared.request.model_dump_json()
    with pytest.raises(AiFailure) as error:
        asyncio.run(
            AiSession().send(
                prepared,
                consent,
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(lambda _: response(reply(model, value))),
            )
        )
    assert error.value.code in (AiErrorCode.RESPONSE_INVALID, AiErrorCode.RESPONSE_UNSAFE)
    assert prepared.request.model_dump_json() == before


@pytest.mark.parametrize("model", MODELS)
def test_cap_stop_missing_blocks_model_mismatch_and_duplicate_json_rejected(model: Model) -> None:
    original = reply(model)
    broken = []
    missing = copy.deepcopy(original)
    missing.pop(
        "output"
        if model.provider == Provider.OPENAI
        else "content"
        if model.provider == Provider.ANTHROPIC
        else "candidates"
    )
    broken.append(missing)
    stopped = copy.deepcopy(original)
    capped = copy.deepcopy(original)
    if model.provider == Provider.OPENAI:
        stopped["status"] = "incomplete"
        capped["usage"]["output_tokens"] = 1024
        wrong = copy.deepcopy(original)
        wrong["model"] = "other-model"
        broken.append(wrong)
    elif model.provider == Provider.ANTHROPIC:
        stopped["stop_reason"] = "max_tokens"
        capped["usage"]["output_tokens"] = 1024
        wrong = copy.deepcopy(original)
        wrong["model"] = "other-model"
        broken.append(wrong)
    else:
        stopped["candidates"][0]["finishReason"] = "MAX_TOKENS"
        capped["usageMetadata"]["candidatesTokenCount"] = 1024
    broken.extend((stopped, capped))
    for value in broken:
        with pytest.raises(AiFailure):
            adapter(model.provider).parse(encode(value), model)
    with pytest.raises(AiFailure):
        adapter(model.provider).parse(b'{"a":1,"a":2}', model)


@pytest.mark.parametrize("model", MODELS)
def test_missing_usage_stays_unknown(model: Model) -> None:
    value = reply(model)
    value.pop("usageMetadata" if model.provider == Provider.GOOGLE else "usage")
    data, usage = adapter(model.provider).parse(encode(value), model)
    assert validate_explanation(data, general_request("profiles"))
    assert usage.input_tokens is usage.output_tokens is usage.estimated_cost is None


@pytest.mark.parametrize("field", ["payload", "revision", "prompt_version", "model"])
def test_stale_review_fails_before_any_attempt(field: str) -> None:
    prepared, consent = reviewed(MODELS[0])
    if field == "model":
        prepared = replace(prepared, model=MODELS[1])
    elif field == "payload":
        prepared = replace(prepared, payload=prepared.payload + b" ")
    else:
        prepared = replace(prepared, **{field: "changed"})
    session = AiSession()

    def forbidden(_: httpx.Request) -> httpx.Response:
        pytest.fail("Stale consent reached transport")

    with pytest.raises(AiFailure) as error:
        asyncio.run(
            session.send(
                prepared,
                consent,
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(forbidden),
            )
        )
    assert error.value.code == AiErrorCode.STALE_CONSENT
    assert session.allowance.attempts == 0


def test_allowlist_rejects_arbitrary_model_and_disabled_configuration() -> None:
    with pytest.raises(AiFailure):
        selected_model(Provider.OPENAI, "invented-unreviewed-model")
    with pytest.raises(AiFailure):
        prepare(
            AiConfiguration(),
            general_request("profiles"),
            context_revision("general"),
            DisclosurePolicy(),
        )


def test_shipped_manifest_matches_fixed_routes_without_claiming_live_verification() -> None:
    manifest = json.loads(files("wfdiag").joinpath("resources/ai/providers-v1.json").read_text())
    assert manifest["prompt_version"] == "system-v1"
    assert len(manifest["models"]) == len(MODELS)
    for row, model in zip(manifest["models"], MODELS, strict=True):
        for field in (
            "provider",
            "model",
            "host",
            "route",
            "api_version",
            "output_parameter",
            "live_verified",
        ):
            assert row[field] == getattr(model, field)
        assert row["output_limit"] == 1024 and not row["live_verified"]
