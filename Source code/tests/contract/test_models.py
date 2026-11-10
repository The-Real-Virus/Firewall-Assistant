import json
from typing import Any

import pytest
from pydantic import ValidationError

from wfdiag.contracts.models import Finding, Intent, ManifestFile, Proposal, SourceStatus


def test_handbook_unconfirmed_intent_is_valid_data_not_authorization(
    intent_data: dict[str, Any],
) -> None:
    intent = Intent.model_validate_json(json.dumps(intent_data))
    assert intent.application_identity_confirmed is False
    assert intent.local_port == 8765


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "2.0"),
        ("protocol", "UDP"),
        ("profile", "Any"),
        ("local_port", "8765"),
        ("local_port", True),
        ("remote_addresses", []),
        ("remote_addresses", ["0.0.0.0/0"]),
        ("remote_addresses", ["192.168.1.8/24"]),
        ("application_path", r"C:\Training\*.exe"),
        ("application_path", "relative.exe"),
        ("application_path", r"C:\Training\App.exe:stream"),
        ("application_identity_confirmed", "true"),
        ("purpose", "x" * 501),
    ],
)
def test_intent_rejects_unsafe_or_coerced_fields(
    intent_data: dict[str, Any], field: str, value: object
) -> None:
    intent_data[field] = value
    with pytest.raises(ValidationError):
        Intent.model_validate_json(json.dumps(intent_data))


def test_outbound_intent_cannot_fix_ephemeral_client_port(intent_data: dict[str, Any]) -> None:
    intent_data.update(direction="outbound", remote_port=443)
    with pytest.raises(ValidationError, match="no fixed local client port"):
        Intent.model_validate_json(json.dumps(intent_data))
    intent_data["local_port"] = None
    assert Intent.model_validate_json(json.dumps(intent_data)).remote_port == 443


def test_extra_intent_command_field_rejected(intent_data: dict[str, Any]) -> None:
    intent_data["command"] = "anything"
    with pytest.raises(ValidationError):
        Intent.model_validate_json(json.dumps(intent_data))


@pytest.mark.parametrize(
    "category",
    ["EXPLICIT_BLOCK", "EVIDENCE_GAP", "NO_RELEVANT_EVENT", "LOCAL_RULE_MERGE_RESTRICTED"],
)
def test_refusal_category_cannot_claim_eligibility(
    finding_data: dict[str, Any], category: str
) -> None:
    finding_data.update(category=category, proposal_eligible=True, refusal_codes=[])
    with pytest.raises(ValidationError):
        Finding.model_validate_json(json.dumps(finding_data))


@pytest.mark.parametrize(
    "filename", ["../host.json", "C:\\host.json", "host.json:secret", "unexpected.json"]
)
def test_manifest_has_known_relative_files_only(filename: str) -> None:
    with pytest.raises(ValidationError):
        ManifestFile.model_validate_json(
            json.dumps({"filename": filename, "byte_length": 1, "sha256": "a" * 64})
        )


@pytest.mark.parametrize("timestamp", ["2026-11-01T10:00:00", "2026-11-01T10:00:00+05:00"])
def test_source_windows_require_explicit_utc(timestamp: str) -> None:
    with pytest.raises(ValidationError):
        SourceStatus.model_validate_json(
            json.dumps(
                {
                    "source": "events",
                    "state": "empty",
                    "window_start_utc": timestamp,
                    "window_end_utc": timestamp,
                }
            )
        )


def test_proposal_schema_cannot_be_executable() -> None:
    prop = Proposal.model_json_schema()["properties"]
    assert prop["executable"]["const"] is False
    assert prop["action"]["const"] == "Allow"
    assert prop["protocol"]["const"] == "TCP"
