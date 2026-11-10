"""Offline transport fixture; no live provider compatibility claim."""

import asyncio
import json

import httpx

from wfdiag.ai.contracts import AiRequest, validate_explanation


def test_canned_transport_needs_no_key_or_network() -> None:
    request = AiRequest.model_validate_json(
        json.dumps(
            {
                "task_mode": "general_help",
                "question": "What is a firewall profile?",
                "approved_context": None,
                "allowed_next_steps": ["GLOSSARY_PROFILE"],
            }
        )
    )
    response = {
        "schema_version": "1.0",
        "status": "answered",
        "explanation": "A profile represents a network policy context.",
        "finding_refs": [],
        "evidence_refs": [],
        "next_step_ids": ["GLOSSARY_PROFILE"],
        "limitations": [],
    }
    observed = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        observed.append(incoming.content)
        assert "authorization" not in incoming.headers
        return httpx.Response(200, json=response)

    async def exercise() -> bytes:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), trust_env=False
        ) as client:
            result = await client.post(
                "https://offline-fixture.invalid/contract",
                content=request.model_dump_json().encode(),
            )
            return result.content

    explanation = validate_explanation(asyncio.run(exercise()), request)
    assert explanation.status == "answered"
    assert len(observed) == 1
