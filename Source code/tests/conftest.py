"""Synthetic contract data. Never derived from this host's evidence."""

from typing import Any

import pytest


@pytest.fixture
def intent_data() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "application_path": r"C:\Training\ExampleApp.exe",
        "application_identity_confirmed": False,
        "direction": "inbound",
        "protocol": "TCP",
        "profile": "Private",
        "remote_addresses": ["192.168.56.20/32"],
        "local_port": 8765,
        "remote_port": None,
        "purpose": "Synthetic contract example, not operational authorization",
    }


@pytest.fixture
def finding_data() -> dict[str, Any]:
    return {
        "finding_id": "F001",
        "category": "EXPLICIT_BLOCK",
        "evidence_grade": "confirmed",
        "summary": "Synthetic explicit block",
        "observation": "Synthetic evidence only",
        "evidence_refs": ["events:1"],
        "candidate_rules": [],
        "policy_snapshot_utc": None,
        "relevance": "relevant",
        "limitations": [],
        "alternative_explanations": [],
        "next_steps": ["REVIEW_POLICY_OWNER"],
        "proposal_eligible": False,
        "refusal_codes": ["EXPLICIT_BLOCK"],
    }


@pytest.fixture
def context_data() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "finding_ref": "FABCDEFGH",
        "category": "EXPLICIT_BLOCK",
        "evidence_grade": "confirmed",
        "completeness": "complete",
        "relevance": "relevant",
        "proposal_eligible": False,
        "refusal_codes": ["EXPLICIT_BLOCK"],
        "protocol": "TCP",
        "direction": "outbound",
        "address_family": "IPv6",
        "service_port": 443,
        "application_alias": "Application A",
        "peer_alias": "Peer B",
        "observations": [{"reference": "EABCDEFGH", "code": "EXPLICIT_BLOCK"}],
        "limitation_codes": [],
        "allowed_next_steps": ["REVIEW_POLICY_OWNER"],
    }
