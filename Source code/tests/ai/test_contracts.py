import json
from typing import Any

import pytest
from pydantic import ValidationError

from wfdiag.ai.contracts import AiConfiguration, AiContext, AiRequest, validate_explanation


def request_for(context_data: dict[str, Any]) -> AiRequest:
    return AiRequest.model_validate_json(
        json.dumps(
            {
                "task_mode": "selected_finding",
                "question": "Why is this proposal withheld?",
                "approved_context": context_data,
                "allowed_next_steps": ["REVIEW_POLICY_OWNER"],
            }
        )
    )


def answer() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "status": "answered",
        "explanation": "The supplied finding records an explicit block.",
        "finding_refs": ["FABCDEFGH"],
        "evidence_refs": ["EABCDEFGH"],
        "next_step_ids": ["REVIEW_POLICY_OWNER"],
        "limitations": [],
    }


def test_first_run_needs_no_provider_model_key_or_client() -> None:
    settings = AiConfiguration()
    assert settings.enabled is False
    assert settings.provider is None
    assert settings.model is None
    assert settings.remember_key is False
    assert "key" not in settings.model_dump()


def test_context_cannot_carry_raw_identifiers(context_data: dict[str, Any]) -> None:
    for field, value in [
        ("hostname", "canary-host"),
        ("application_path", r"C:\Private\App.exe"),
        ("raw_xml", "<Event/>"),
        ("api_key", "canary-secret"),
    ]:
        with pytest.raises(ValidationError):
            AiContext.model_validate_json(json.dumps(context_data | {field: value}))


def test_context_cannot_upgrade_explicit_block(context_data: dict[str, Any]) -> None:
    context_data.update(proposal_eligible=True, refusal_codes=[])
    with pytest.raises(ValidationError):
        AiContext.model_validate_json(json.dumps(context_data))


def test_six_observations_are_rejected(context_data: dict[str, Any]) -> None:
    context_data["observations"] = [
        {"reference": f"EABCDEFG{i}", "code": "EXPLICIT_BLOCK"} for i in range(6)
    ]
    with pytest.raises(ValidationError):
        AiContext.model_validate_json(json.dumps(context_data))


@pytest.mark.parametrize(
    "patch",
    [
        {"finding_refs": ["FUNKNOWNX"]},
        {"evidence_refs": ["EUNKNOWNX"]},
        {"next_step_ids": ["VERIFY_INTENT"]},
        {"execute": "anything"},
        {"schema_version": "2.0"},
        {"status": "certain"},
        {"explanation": "x" * 4001},
        {"limitations": ["x" * 301]},
        {"limitations": ["x"] * 6},
    ],
)
def test_invalid_provider_answer_never_becomes_explanation(
    context_data: dict[str, Any], patch: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        validate_explanation(json.dumps(answer() | patch).encode(), request_for(context_data))


def test_valid_references_are_accepted_without_modifying_context(
    context_data: dict[str, Any],
) -> None:
    request = request_for(context_data)
    before = request.model_dump_json()
    result = validate_explanation(json.dumps(answer()).encode(), request)
    assert result.finding_refs == ("FABCDEFGH",)
    assert request.model_dump_json() == before


def test_general_help_rejects_case_context(context_data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AiRequest.model_validate_json(
            json.dumps(
                {
                    "task_mode": "general_help",
                    "question": "What is a profile?",
                    "approved_context": context_data,
                    "allowed_next_steps": [],
                }
            )
        )
