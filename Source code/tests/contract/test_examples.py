import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from wfdiag.contracts.models import Analysis, Event, Host, Intent, Manifest, Proposal, Rule


def records() -> dict[str, object]:
    path = Path(__file__).parents[2] / "examples/contract-examples.json"
    result: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))["records"]
    return result


@pytest.mark.parametrize(
    "name,model",
    [
        ("host", Host),
        ("intent", Intent),
        ("manifest", Manifest),
        ("event", Event),
        ("rule", Rule),
        ("analysis", Analysis),
        ("proposal", Proposal),
    ],
)
def test_documented_schema_examples_round_trip(
    name: str, model: type[Host | Intent | Manifest | Event | Rule | Analysis | Proposal]
) -> None:
    value = model.model_validate_json(json.dumps(records()[name]))
    assert model.model_validate_json(value.model_dump_json()) == value


@pytest.mark.parametrize("value", [True, 0, 1, "false", None])
def test_proposal_requires_actual_false_boolean(value: object) -> None:
    value_data = records()["proposal"]
    assert isinstance(value_data, dict)
    proposal = dict(value_data)
    proposal["executable"] = value
    with pytest.raises(ValidationError):
        Proposal.model_validate_json(json.dumps(proposal))


def test_manifest_cannot_call_failed_required_events_complete() -> None:
    manifest = records()["manifest"]
    assert isinstance(manifest, dict)
    manifest["sources"][3]["state"] = "access_denied"
    with pytest.raises(ValidationError, match="cannot be marked complete"):
        Manifest.model_validate_json(json.dumps(manifest))
