"""Synthetic ground truth. No native policy/collector acceptance follows from these tests."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from wfdiag.analysis.engine import analyze_case
from wfdiag.contracts.base import Contract
from wfdiag.contracts.models import (
    Analysis,
    Event,
    FirewallProfile,
    Intent,
    Manifest,
    NetworkSnapshot,
    Rule,
)


def changed[T: Contract](value: T, **changes: object) -> T:
    data = value.model_dump(mode="json")
    data.update(changes)
    return type(value).model_validate_json(json.dumps(data))


@dataclass
class Scenario:
    manifest: Manifest
    profiles: tuple[FirewallProfile, ...]
    rules: tuple[Rule, ...]
    event: Event
    intent: Intent
    network: NetworkSnapshot | None

    def analyze(self, events: tuple[Event, ...] | None = None) -> Analysis:
        actual = (self.event,) if events is None else events
        sources = [s.model_dump(mode="json") for s in self.manifest.sources]
        next(s for s in sources if s["source"] == "events")["records"] = len(actual)
        manifest = changed(self.manifest, sources=sources)
        return analyze_case(
            manifest,
            self.profiles,
            self.rules,
            actual,
            intent=self.intent,
            network=self.network,
            analyzed_at_utc=datetime(2026, 11, 1, 0, 11, tzinfo=UTC),
        )


@pytest.fixture
def scenario() -> Scenario:
    examples = json.loads(
        (Path(__file__).parents[2] / "examples/contract-examples.json").read_text(encoding="utf-8")
    )["records"]
    manifest_data = examples["manifest"]
    manifest_data["host"].update(build="19045.0", windows_product_type=1)
    manifest_data.update(policy_snapshot_utc="2026-11-01T00:05:30Z", policy_change_observed=False)
    manifest_data["sources"].append(
        {
            "source": "network",
            "state": "complete",
            "window_start_utc": "2026-11-01T00:00:00Z",
            "window_end_utc": "2026-11-01T00:10:00Z",
            "records": 1,
            "warnings": [],
        }
    )
    manifest_data["files"].append(
        {"filename": "network.json", "byte_length": 0, "sha256": "0" * 64}
    )
    manifest_data["sources"][3].update(state="complete", records=1)
    event = Event.model_validate_json(json.dumps(examples["event"]))
    event = changed(
        event,
        application_canonical=examples["intent"]["application_path"],
        interface_index=7,
        warnings=[],
    )
    intent = changed(
        Intent.model_validate_json(json.dumps(examples["intent"])),
        application_identity_confirmed=True,
    )
    profiles = tuple(
        FirewallProfile.model_validate_json(
            json.dumps(
                {
                    "profile": p,
                    "enabled": True,
                    "active": p == "Private",
                    "default_inbound": "Block",
                    "default_outbound": "Block",
                    "allow_local_rule_merge": True,
                    "policy_source": "Synthetic local policy",
                    "policy_source_type": "local",
                    "source_ref": "profiles:" + p,
                }
            )
        )
        for p in ("Domain", "Private", "Public")
    )
    network = NetworkSnapshot.model_validate_json(
        json.dumps(
            {
                "observed_at_utc": "2026-11-01T00:05:30Z",
                "interfaces": [
                    {
                        "interface_index": 7,
                        "name": "Synthetic interface",
                        "addresses": ["192.168.56.10"],
                        "active_profile": "Private",
                        "state": "up",
                        "source_ref": "network:7",
                    }
                ],
            }
        )
    )
    return Scenario(
        Manifest.model_validate_json(json.dumps(manifest_data)),
        profiles,
        (),
        event,
        intent,
        network,
    )


def rule(s: Scenario, **changes: object) -> Rule:
    conditions = {
        "programs": [s.intent.application_path],
        "protocols": ["TCP"],
        "local_ports": ["8765"],
        "remote_ports": ["Any"],
        "local_addresses": ["Any"],
        "remote_addresses": ["Any"],
        "services": [],
        "interfaces": [],
        "interface_types": [],
        "security": [],
    }
    data = {
        "rule_id": "R-block",
        "display_name": "Display name is not an identity",
        "enabled": True,
        "action": "Block",
        "direction": "inbound",
        "profiles": ["Private"],
        "policy_source": "Synthetic local policy",
        "policy_source_type": "local",
        "snapshot_utc": "2026-11-01T00:05:30Z",
        "conditions": conditions,
        "filter_errors": [],
        "source_ref": "rules:R-block",
    }
    data.update(changes)
    return Rule.model_validate_json(json.dumps(data))


def condition_rule(s: Scenario, **conditions: object) -> Rule:
    original = rule(s)
    data = original.conditions.model_dump(mode="json")
    data.update(conditions)
    return changed(original, conditions=data)
