"""Synthetic evidence consistency only. These fixtures never confer a real gate pass."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError


@pytest.fixture
def verifier():
    path = Path(__file__).parents[2] / "scripts/verify_release_evidence.py"
    spec = importlib.util.spec_from_file_location("wfdiag_release_verifier_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def invented_candidate(tmp_path):
    """Invented source/artifacts and attestations; not copied into release records."""
    commit = "a" * 40
    now = "2026-11-04T00:00:00Z"

    def write(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    proof = {
        "file": "invented-proof.json",
        "sha256": write("invented-proof.json", {"test_fixture": True}),
        "source_commit": commit,
        "status": "pass",
        "actor": "synthetic test fixture, not an actual reviewer",
        "recorded_at_utc": now,
    }
    gate = {
        "gate_id": "G0",
        "status": "pass",
        "source_revision": commit,
        "recorded_at_utc": now,
        "evidence": [
            {
                "command": "invented-test-only",
                "cwd": str(tmp_path),
                "platform": "invented",
                "timestamp_utc": now,
                "exit_code": 0,
                "log": "invented-proof.json",
                "actor": "codex",
                "source_revision": commit,
                "artifact_sha256": None,
            }
        ],
        "blockers": [],
        "decision_by": "synthetic fixture only",
    }
    gates = {}
    for number in range(9):
        key = f"G{number}"
        name = f"{key}.json"
        write(name, {**gate, "gate_id": key})
        gates[key] = name
    locks = {
        name: write(name, {"synthetic": True})
        for name in ("requirements.txt", "requirements-desktop-ai.txt", "requirements-dev.txt")
    }
    manifest = {
        "schema_version": 1,
        "stage": "release",
        "version": "1.0.0",
        "source_commit": commit,
        "artifacts": [{k: proof[k] for k in ("file", "sha256", "source_commit")}],
        "locks": locks,
        "gates": gates,
        "tested_systems": [
            {
                "windows": "Windows 10",
                "edition": "invented fixture",
                "build": "19045.1234",
                "architecture": "x64",
                "evidence": proof,
            }
        ],
        "scenarios": {f"T{n:02}": proof.copy() for n in range(1, 25)},
        **{
            name: proof.copy()
            for name in (
                "support_matrix",
                "native_validation",
                "security_review",
                "packaged_journeys",
                "performance",
                "ai_evaluation",
                "pilot",
                "handbook",
                "signing",
                "owner_decision",
            )
        },
        "signing_status": "unsigned",
        "known_critical": 0,
        "known_high": 0,
        "unknown_severity_findings": 0,
    }
    path = tmp_path / "invented-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path, manifest


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def test_complete_invented_consistency_does_not_grant_approval(verifier, invented_candidate):
    path, _ = invented_candidate
    assert verifier.verify_manifest(path, path.parent, release=True) == []


@pytest.mark.parametrize("field", ["owner_decision", "handbook", "support_matrix", "pilot"])
def test_missing_required_record_cannot_pass(verifier, invented_candidate, field):
    path, manifest = invented_candidate
    del manifest[field]
    save(path, manifest)
    with pytest.raises(ValidationError):
        verifier.verify_manifest(path, path.parent, release=True)


@pytest.mark.parametrize(
    "change",
    [
        {"stage": "evaluation"},
        {"version": "0.1.0"},
        {"version": "1.0.0-rc.1"},
        {"known_high": 1},
        {"known_critical": 1},
        {"unknown_severity_findings": 1},
        {"owner_decision": None},
    ],
)
def test_unready_state_is_blocked(verifier, invented_candidate, change):
    path, manifest = invented_candidate
    manifest.update(change)
    save(path, manifest)
    assert verifier.verify_manifest(path, path.parent, release=True)


@pytest.mark.parametrize("field", ["schema_version", "known_high", "known_critical"])
def test_boolean_is_not_an_integer(verifier, invented_candidate, field):
    path, manifest = invented_candidate
    manifest[field] = True
    save(path, manifest)
    with pytest.raises(ValidationError):
        verifier.verify_manifest(path, path.parent, release=True)


@pytest.mark.parametrize(
    "change",
    [
        {"evidence": []},
        {"blockers": ["native testing unavailable"]},
        {"decision_by": None},
        {"source_revision": None},
    ],
)
def test_empty_or_blocked_gate_cannot_be_pass(verifier, invented_candidate, change):
    path, _ = invented_candidate
    gate_path = path.parent / "G2.json"
    gate = json.loads(gate_path.read_text("utf-8"))
    gate.update(change)
    save(gate_path, gate)
    with pytest.raises(ValidationError):
        verifier.verify_manifest(path, path.parent, release=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("exit_code", None),
        ("exit_code", 1),
        ("exit_code", False),
        ("source_revision", "b" * 40),
    ],
)
def test_failed_unrun_or_stale_command_rejects_gate(verifier, invented_candidate, field, value):
    path, _ = invented_candidate
    gate_path = path.parent / "G2.json"
    gate = json.loads(gate_path.read_text("utf-8"))
    gate["evidence"][0][field] = value
    save(gate_path, gate)
    with pytest.raises(ValidationError):
        verifier.verify_manifest(path, path.parent, release=True)


@pytest.mark.parametrize("field", ["source_commit", "sha256"])
def test_stale_or_modified_proof_fails(verifier, invented_candidate, field):
    path, manifest = invented_candidate
    manifest["pilot"][field] = "b" * (40 if field == "source_commit" else 64)
    save(path, manifest)
    with pytest.raises(ValueError):
        verifier.verify_manifest(path, path.parent, release=True)


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/absolute",
        "C:/outside",
        "data:stream",
        "x\\y",
        "NUL.txt",
        "trailing.",
        "foo\x00bar",
        "./CON",
        "foo?.json",
    ],
)
def test_unsafe_reference_is_rejected_before_filesystem(verifier, tmp_path, name):
    with pytest.raises(ValueError):
        verifier.local_file(tmp_path, name)


def test_candidate_review_requires_every_prior_gate_and_respects_rejection(
    verifier, invented_candidate
):
    path, manifest = invented_candidate
    manifest.update(stage="release_candidate", version="1.0.0-rc.1", owner_decision=None)
    save(path, manifest)
    gate_path = path.parent / "G8.json"
    gate = json.loads(gate_path.read_text("utf-8"))
    gate.update(status="pending", evidence=[], decision_by=None)
    save(gate_path, gate)
    assert verifier.verify_manifest(path, path.parent, release=False) == []
    gate["status"] = "fail"
    save(gate_path, gate)
    assert "G8 lacks a passing decision" in verifier.verify_manifest(
        path, path.parent, release=False
    )
    gate["status"] = "pending"
    save(gate_path, gate)
    prior = path.parent / "G4.json"
    value = json.loads(prior.read_text("utf-8"))
    value.update(status="blocked", blockers=["native ACL unavailable"])
    save(prior, value)
    assert "G4 lacks a passing decision" in verifier.verify_manifest(
        path, path.parent, release=False
    )


def test_unknown_or_incomplete_manifest_and_aliases_rejected(verifier, invented_candidate):
    path, manifest = invented_candidate
    manifest["invented_approval"] = True
    save(path, manifest)
    with pytest.raises(ValidationError):
        verifier.verify_manifest(path, path.parent, release=True)
    del manifest["invented_approval"]
    manifest["artifacts"] *= 2
    save(path, manifest)
    with pytest.raises(ValueError, match="Duplicate"):
        verifier.verify_manifest(path, path.parent, release=True)


def test_required_native_scenario_cannot_be_omitted_or_skipped(verifier, invented_candidate):
    path, manifest = invented_candidate
    manifest["scenarios"]["T23"]["status"] = "blocked"
    save(path, manifest)
    assert "T23 has no passing acceptance" in verifier.verify_manifest(
        path, path.parent, release=True
    )
    del manifest["scenarios"]["T23"]
    save(path, manifest)
    with pytest.raises(ValidationError):
        verifier.verify_manifest(path, path.parent, release=True)


def test_current_actual_g1_record_schema(verifier):
    path = Path(__file__).parents[2] / "docs/evidence/G1-contracts-20261104.json"
    record = verifier.GateObservation.model_validate_json(path.read_bytes())
    assert record.gate_id == "G1" and record.status == "pass"
    assert len(record.evidence) == 4


def test_release_manifest_schema_has_no_drift(verifier):
    path = Path(__file__).parents[2] / "docs/evidence/templates/release-manifest.schema.json"
    assert json.loads(path.read_text("utf-8")) == verifier.ReleaseManifest.model_json_schema()
