import base64
import json
from pathlib import Path

import pytest

from wfdiag.ai.context import SessionAliases, general_request, selected_request
from wfdiag.ai.contracts import (
    AiConfiguration,
    AiErrorCode,
    Explanation,
    Provider,
    validate_explanation,
)
from wfdiag.ai.policy import (
    AiFailure,
    DisclosurePolicy,
    consent_for,
    require_provider_policy,
    validate_content,
    verify_consent,
)
from wfdiag.contracts.models import Analysis

ROOT = Path(__file__).parents[2]


def case() -> Analysis:
    return Analysis.model_validate_json((ROOT / "examples/expected-analysis.json").read_bytes())


def test_context_allowlist_omits_canaries_and_preserves_engine_bytes() -> None:
    data = case().model_dump(mode="json")
    data["host"]["hostname"] = "CANARY_HOST"
    data["intent"]["purpose"] = "CANARY_PURPOSE"
    data["findings"][0]["observation"] = "CANARY_OBSERVATION"
    data["findings"][0]["limitations"] = ["CANARY_LIMITATION"]
    analysis = Analysis.model_validate_json(json.dumps(data))
    original = analysis.model_dump_json()
    request, revision, policy = selected_request(
        analysis,
        analysis.findings[0].finding_id,
        "Which approved evidence is missing?",
        SessionAliases(),
        selection_revision="selection-one",
    )
    body = request.model_dump_json().encode()
    assert b"CANARY" not in body and b"192.168" not in body and b"Training" not in body
    assert request.approved_context is not None
    assert request.approved_context.category == analysis.findings[0].category
    assert request.approved_context.evidence_grade == analysis.findings[0].evidence_grade
    assert request.approved_context.proposal_eligible == analysis.findings[0].proposal_eligible
    assert len(revision) == 64 and "CANARY" not in repr(policy)
    assert analysis.model_dump_json() == original
    policy.check_json(body)


@pytest.mark.parametrize(
    "text",
    [
        r"C:\Private\app.exe",
        "C%3A%5CPrivate%5Capp.exe",
        r"C\u003a\u005cPrivate\u005capp.exe",
        "Ｃ：\\Private\\app.exe",
        "2001:db8::1",
        "192.0.2.10/32",
        "https://unapproved.invalid",
        "CANARY_SECRET_VALUE",
        "sk-NotARealKey123456789",
        "person@example.invalid",
        base64.b64encode(b"C:\\Private\\app.exe").decode(),
        "0x" + b"CANARY_SECRET".hex(),
        "C\u200b:\\Private\\app.exe",
    ],
)
def test_encoded_or_direct_sensitive_question_is_blocked(text: str) -> None:
    with pytest.raises(AiFailure) as error:
        DisclosurePolicy().check_text(text, character_limit=1000)
    assert error.value.code == AiErrorCode.DISCLOSURE
    assert text not in str(error.value)


def test_case_names_and_key_sentinels_are_checked_in_final_json() -> None:
    policy = DisclosurePolicy(["PrivateHostName", "LocalOnlySecretSentinel"])
    for item in (
        b'{"question":"PrivateHostName"}',
        b'{"question":"LocalOnlySecretSentinel"}',
        b'{"question":"Private\\u0048ostName"}',
    ):
        with pytest.raises(AiFailure):
            policy.check_json(item)
    policy.check_json(b'{"question":"Why was this proposal withheld?"}')


def test_aliases_are_session_scoped_and_selection_changes_revision() -> None:
    analysis = case()
    aliases = SessionAliases()
    values = []
    for selection in ("one", "one", "two"):
        request, revision, _ = selected_request(
            analysis,
            analysis.findings[0].finding_id,
            "Explain the evidence limitations.",
            aliases,
            selection_revision=selection,
        )
        values.append((request.approved_context.finding_ref, revision))
    assert values[0] == values[1] and values[0] != values[2]
    aliases.clear()
    request, _, _ = selected_request(
        analysis,
        analysis.findings[0].finding_id,
        "Explain the evidence limitations.",
        aliases,
        selection_revision="one",
    )
    assert request.approved_context.finding_ref != values[0][0]
    assert "synthetic" not in repr(aliases)


def test_consent_binds_exact_bytes_destination_model_and_revisions() -> None:
    arguments = {
        "provider": Provider.OPENAI,
        "model": "offline-fixture",
        "payload": b'{"question":"Explain"}',
        "revision": "a" * 64,
        "prompt_version": "1",
    }
    consent = consent_for(**arguments)
    verify_consent(consent, **arguments)
    for patch in (
        {"provider": Provider.GOOGLE},
        {"model": "other-fixture"},
        {"payload": b'{"question": "Explain"}'},
        {"revision": "b" * 64},
        {"prompt_version": "2"},
    ):
        with pytest.raises(AiFailure) as error:
            verify_consent(consent, **(arguments | patch))
        assert error.value.code == AiErrorCode.STALE_CONSENT


def test_general_help_has_no_case_and_final_body_guards_reject_invalid_json() -> None:
    request = general_request("profiles")
    assert request.approved_context is None and request.task_mode == "general_help"
    policy = DisclosurePolicy()
    policy.check_json(request.model_dump_json().encode())
    for data in (
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":' + b"[" * 30 + b"]" * 30 + b"}",
        b"x" * 65537,
    ):
        with pytest.raises(AiFailure):
            policy.check_json(data)


@pytest.mark.parametrize(
    "prose",
    [
        "New-NetFirewallRule -Action Allow",
        "Add an allow exception to fix the block.",
        "You should disable the firewall.",
        "<a href='unapproved'>Read this</a>",
        "[Follow this](file:///private)",
        "Run the following steps.",
        "Use C:\\Private\\app.exe",
        "Contact CANARY_PERSON",
    ],
)
def test_unsafe_model_prose_is_not_a_trusted_explanation(prose: str) -> None:
    response = Explanation(
        schema_version="1.0",
        status="answered",
        explanation=prose,
        finding_refs=(),
        evidence_refs=(),
        next_step_ids=(),
        limitations=(),
    )
    with pytest.raises(AiFailure) as error:
        validate_content(response, DisclosurePolicy())
    assert error.value.code == AiErrorCode.RESPONSE_UNSAFE
    assert prose not in str(error.value)


def test_explanatory_refusal_text_remains_separate_and_duplicate_output_is_rejected() -> None:
    answer = {
        "schema_version": "1.0",
        "status": "answered",
        "explanation": "An additional allow exception does not override an explicit block. The engine's refusal remains in effect.",
        "finding_refs": [],
        "evidence_refs": [],
        "next_step_ids": [],
        "limitations": [],
    }
    request = general_request("profiles")
    response = validate_explanation(json.dumps(answer).encode(), request)
    assert validate_content(response, DisclosurePolicy()) is response
    invalid = json.dumps(answer)[:-1] + ',"status":"refused"}'
    with pytest.raises(ValueError, match="Duplicate"):
        validate_explanation(invalid.encode(), request)


def test_google_policy_restriction_is_not_bypassed_by_account_or_model_selection() -> None:
    analysis = case()
    request, _, _ = selected_request(
        analysis,
        analysis.findings[0].finding_id,
        "Explain the limitations.",
        SessionAliases(),
        selection_revision="test-selection",
    )
    config = AiConfiguration(enabled=True, provider=Provider.GOOGLE, model="offline-fixture")
    require_provider_policy(config, general_request("profiles"))
    require_provider_policy(config, request, trusted_synthetic=True)
    with pytest.raises(AiFailure):
        require_provider_policy(config, request)
    config = config.model_copy(
        update={"organization_permission_confirmed": True, "provider_policy_confirmed": True}
    )
    with pytest.raises(AiFailure):
        require_provider_policy(config, request)
    # These flags are explicitly user-supplied permissions, never verified billing facts.
    require_provider_policy(config.model_copy(update={"policy_mode": "permitted_case"}), request)
    with pytest.raises(AiFailure):
        require_provider_policy(AiConfiguration(), general_request("profiles"))


def test_normalization_expansion_and_encoded_commands_are_rejected() -> None:
    with pytest.raises(AiFailure):
        DisclosurePolicy().check_text("\ufdfa" * 1000, character_limit=1000)
    with pytest.raises(AiFailure):
        DisclosurePolicy().check_text(r"\uD800", character_limit=1000)
    command = b"New-NetFirewallRule -Action Allow"
    encoded = base64.b64encode(base64.b64encode(command)).decode()
    for prose in (encoded, "0x" + command.hex()):
        response = Explanation(
            schema_version="1.0",
            status="answered",
            explanation=prose,
            finding_refs=(),
            evidence_refs=(),
            next_step_ids=(),
            limitations=(),
        )
        with pytest.raises(AiFailure) as error:
            validate_content(response, DisclosurePolicy())
        assert error.value.code == AiErrorCode.RESPONSE_UNSAFE
