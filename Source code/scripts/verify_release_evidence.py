"""Read-only local evidence consistency checks. Never grants approval, signs or publishes."""

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator

from wfdiag.contracts.base import Contract, absolute_local_path, actual_integer, utc_only
from wfdiag.storage.atomic_write import check_plain_path
from wfdiag.storage.records import read_record

Sha = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Commit = Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
GateId = Literal["G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"]
Status = Literal["pending", "pass", "fail", "blocked"]
Text = Annotated[str, Field(min_length=1, max_length=4096)]
ALL_GATES = {f"G{n}" for n in range(9)}


class CommandObservation(Contract):
    command: Text
    cwd: Text
    platform: Text
    timestamp_utc: datetime
    exit_code: Annotated[int, BeforeValidator(actual_integer)] | None
    log: Text
    actor: Literal["codex", "owner", "independent_reviewer"]
    source_revision: Text
    artifact_sha256: Sha | None

    @model_validator(mode="after")
    def actual_values(self) -> Self:
        utc_only(self.timestamp_utc)
        if self.exit_code is not None:
            actual_integer(self.exit_code)
        return self


class GateObservation(Contract):
    gate_id: GateId
    status: Status
    source_revision: Commit | None
    recorded_at_utc: datetime
    evidence: Annotated[tuple[CommandObservation, ...], Field(max_length=100)]
    blockers: Annotated[tuple[Text, ...], Field(max_length=100)]
    decision_by: Text | None

    @model_validator(mode="after")
    def observed_pass(self) -> Self:
        utc_only(self.recorded_at_utc)
        if self.status == "pass" and (
            not self.evidence
            or self.blockers
            or not self.source_revision
            or not self.decision_by
            or any(e.exit_code != 0 for e in self.evidence)
            or any(e.source_revision != self.source_revision for e in self.evidence)
        ):
            raise ValueError("A gate pass needs actual successful evidence and no blockers")
        return self


class Artifact(Contract):
    file: Text
    sha256: Sha
    source_commit: Commit


class Proof(Artifact):
    status: Status
    actor: Text
    recorded_at_utc: datetime

    @model_validator(mode="after")
    def utc_record(self) -> Self:
        utc_only(self.recorded_at_utc)
        return self


class TestedSystem(Contract):
    windows: Literal["Windows 10", "Windows 11"]
    edition: Text
    build: Annotated[str, Field(pattern=r"^\d+\.\d+$")]
    architecture: Literal["x64"]
    evidence: Proof


class ReleaseManifest(Contract):
    schema_version: Annotated[Literal[1], BeforeValidator(actual_integer)]
    stage: Literal["development", "evaluation", "release_candidate", "release"]
    version: Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+(?:-rc\.\d+)?$")]
    source_commit: Commit
    artifacts: Annotated[tuple[Artifact, ...], Field(min_length=1, max_length=100)]
    locks: Annotated[dict[Text, Sha], Field(min_length=3, max_length=3)]
    gates: Annotated[dict[GateId, Text], Field(min_length=9, max_length=9)]
    tested_systems: Annotated[tuple[TestedSystem, ...], Field(min_length=1, max_length=100)]
    scenarios: Annotated[dict[Text, Proof], Field(min_length=24, max_length=24)]
    support_matrix: Proof
    native_validation: Proof
    security_review: Proof
    packaged_journeys: Proof
    performance: Proof
    ai_evaluation: Proof
    pilot: Proof
    handbook: Proof
    signing: Proof
    owner_decision: Proof | None
    signing_status: Literal["signed", "unsigned"]
    known_critical: Annotated[int, BeforeValidator(actual_integer), Field(ge=0)]
    known_high: Annotated[int, BeforeValidator(actual_integer), Field(ge=0)]
    unknown_severity_findings: Annotated[int, BeforeValidator(actual_integer), Field(ge=0)]


def local_file(root: Path, name: str) -> Path:
    parts = PurePosixPath(name).parts
    if (
        not parts
        or ".." in parts
        or PurePosixPath(name).is_absolute()
        or "\\" in name
        or ":" in name
    ):
        raise ValueError("Evidence references must be plain relative local paths")
    # Apply the product's Windows alias/stream/control-character rules even in portable tests.
    absolute_local_path("C:/evidence/" + name)
    path = root.joinpath(*parts)
    check_plain_path(path)
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("Evidence reference is not a contained plain file")
    return path


def fingerprint(root: Path, artifact: Artifact, commit: str) -> None:
    if artifact.source_commit != commit:
        raise ValueError("Evidence source version differs from candidate")
    path = local_file(root, artifact.file)
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != artifact.sha256:
        raise ValueError("Artifact/evidence hash mismatch")


def verify_manifest(path: Path, root: Path, *, release: bool) -> list[str]:
    """Metadata can be checked for consistency; it cannot authenticate human testimony."""
    manifest = read_record(path, ReleaseManifest, byte_limit=2 * 1024 * 1024)
    blocked = []
    if manifest.stage not in (("release",) if release else ("release_candidate", "release")):
        blocked.append("Candidate stage is development/evaluation")
    if re.match(r"^0\.", manifest.version):
        blocked.append("Development version has not reached the reviewed release scope")
    if release and "-rc." in manifest.version:
        blocked.append("A candidate version is not a stable release")
    if manifest.known_critical or manifest.known_high or manifest.unknown_severity_findings:
        blocked.append("Critical/high or untriaged-severity findings remain")
    if len({a.file.casefold() for a in manifest.artifacts}) != len(manifest.artifacts):
        raise ValueError("Duplicate or Windows-aliased artifact identities")
    for artifact in manifest.artifacts:
        fingerprint(root, artifact, manifest.source_commit)
    required_locks = {"requirements.txt", "requirements-desktop-ai.txt", "requirements-dev.txt"}
    if set(manifest.locks) != required_locks:
        raise ValueError("All three exact dependency locks are required")
    for name, digest in manifest.locks.items():
        fingerprint(
            root,
            Artifact(file=name, sha256=digest, source_commit=manifest.source_commit),
            manifest.source_commit,
        )
    if set(manifest.gates) != ALL_GATES:
        raise ValueError("Every gate G0 through G8 is required")
    if set(manifest.scenarios) != {f"T{number:02}" for number in range(1, 25)}:
        raise ValueError("Every required T01 through T24 outcome must be present")
    for name, proof in manifest.scenarios.items():
        fingerprint(root, proof, manifest.source_commit)
        if proof.status != "pass":
            blocked.append(f"{name} has no passing acceptance")
    for system in manifest.tested_systems:
        fingerprint(root, system.evidence, manifest.source_commit)
        if system.evidence.status != "pass":
            blocked.append("A listed tested system has no passing acceptance")
    for gate_id, name in manifest.gates.items():
        gate = read_record(local_file(root, name), GateObservation, byte_limit=1024 * 1024)
        if gate.gate_id != gate_id or gate.source_revision != manifest.source_commit:
            raise ValueError("Gate identity/source version mismatch")
        if gate.status != "pass" and (release or gate_id != "G8" or gate.status == "fail"):
            blocked.append(f"{gate_id} lacks a passing decision")
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
    ):
        proof = getattr(manifest, name)
        fingerprint(root, proof, manifest.source_commit)
        if proof.status != "pass":
            blocked.append(f"{name} is pending/failed/blocked")
    if manifest.owner_decision is not None:
        fingerprint(root, manifest.owner_decision, manifest.source_commit)
        if manifest.owner_decision.status != "pass":
            blocked.append("Exact owner A05 decision is not approved")
    if release and manifest.owner_decision is None:
        blocked.append("Exact owner A05 decision is missing")
    return blocked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    gate = commands.add_parser("gate", help="Validate one gate record; does not accept a release")
    gate.add_argument("--record", type=Path, required=True)
    release = commands.add_parser(
        "release", help="Require complete consistent local release evidence"
    )
    release.add_argument("--manifest", type=Path, required=True)
    release.add_argument("--artifact-root", type=Path, required=True)
    release.add_argument(
        "--candidate-review",
        action="store_true",
        help="Require G0–G7 before requesting A05; never accepts G8",
    )
    args = parser.parse_args()
    try:
        if args.operation == "gate":
            record = read_record(args.record.absolute(), GateObservation, byte_limit=1024 * 1024)
            print(
                json.dumps(
                    {
                        "record_schema": "valid",
                        "gate": record.gate_id,
                        "observed_status": record.status,
                        "release_accepted": False,
                    }
                )
            )
            return 0
        blocked = verify_manifest(
            args.manifest.absolute(),
            args.artifact_root.absolute(),
            release=not args.candidate_review,
        )
        print(
            json.dumps(
                {
                    "evidence_consistency": "blocked" if blocked else "valid",
                    "blockers": blocked,
                    "release_accepted": False,
                    "note": "Read-only consistency check; actual owner/reviewer decisions remain required",
                }
            )
        )
        return 1 if blocked else 0
    except (OSError, ValueError):
        print(
            json.dumps(
                {
                    "evidence_consistency": "fail",
                    "release_accepted": False,
                    "reason": "Missing/invalid evidence, unsafe reference, hash or version mismatch",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
