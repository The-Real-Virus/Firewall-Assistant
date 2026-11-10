"""Prepare exact synthetic request bytes for later A07 review. Never send or load keys."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from wfdiag.ai.context import general_request
from wfdiag.ai.contracts import AiConfiguration, AiRequest
from wfdiag.ai.models import MODELS
from wfdiag.ai.policy import DisclosurePolicy, context_revision
from wfdiag.ai.providers.base import OUTPUT_LIMIT, PROMPT_VERSION, encode, prompt, response_schema
from wfdiag.ai.service import prepare
from wfdiag.storage.atomic_write import check_plain_path
from wfdiag.storage.json_input import checked_json
from wfdiag.storage.opened_files import OpenedDirectory

ROOT = Path(__file__).resolve().parents[1]
PACKET_VERSION = "2026-11-05-r2"
SUBSET = (
    "explicit-block",
    "default-block",
    "profile-mismatch",
    "managed-policy",
    "unresolved-wfp",
    "evidence-gap",
    "no-relevant-event",
    "ipv6",
    "unresolved-identity",
    "unsupported-protocol",
    "incomplete-capture",
    "unrelated-flow",
)


def packet_files(catalog_raw: bytes) -> dict[str, bytes]:
    catalog = checked_json(catalog_raw, byte_limit=2 * 1024 * 1024, max_depth=24, max_values=100000)
    if not isinstance(catalog, dict) or catalog.get("synthetic_only") is not True:
        raise ValueError("Only the reviewed synthetic catalog is permitted")
    if tuple(catalog.get("live_candidate_subset", ())) != SUBSET:
        raise ValueError("The exact proposed subset must be reviewed after changes")
    cases = catalog["cases"]
    if not isinstance(cases, list) or len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Catalog cases must be distinct")
    selected = {case["id"]: case for case in cases if case["id"] in SUBSET}
    if len(selected) != len(SUBSET):
        raise ValueError("Every proposed scene must be present")
    files: dict[str, bytes] = {}
    rows = []
    for model in MODELS:
        for case_id in (*SUBSET, "packaged-general-profiles"):
            if not re.fullmatch(r"[a-z0-9-]+", case_id):
                raise ValueError("Invalid scene identifier")
            case = selected.get(case_id)
            if case is None:
                request = general_request("profiles")
            else:
                if case["expected"] != "accepted":
                    raise ValueError("Initial live scenes must have a valid outbound request")
                request = AiRequest.model_validate_json(
                    json.dumps(
                        {
                            "task_mode": "selected_finding" if case["context"] else "general_help",
                            "question": case["question"],
                            "approved_context": case["context"],
                            "allowed_next_steps": case["allowed_next_steps"],
                        }
                    )
                )
            prepared = prepare(
                AiConfiguration(enabled=True, provider=model.provider, model=model.model),
                request,
                context_revision({"catalog": catalog["catalog_version"], "case": case_id}),
                DisclosurePolicy(catalog["forbidden_values"]),
                trusted_synthetic=case is not None and case["context"] is not None,
            )
            name = f"{model.provider.value}-{case_id}.json"
            files[name] = prepared.payload
            rows.append(
                {
                    "provider": model.provider.value,
                    "model": model.model,
                    "api_version": model.api_version,
                    "case": case_id,
                    "stage": "packaged_gui" if case is None else "catalog_pending_runner",
                    "destination": f"https://{model.host}{model.route}",
                    "file": name,
                    "bytes": len(prepared.payload),
                    "sha256": hashlib.sha256(prepared.payload).hexdigest(),
                    "attempts": 1,
                    "max_output_tokens": OUTPUT_LIMIT,
                    "live_validation": "blocked",
                    "human_review": "blocked",
                    "expected_facts": case["expected_facts"]
                    if case
                    else ["General profile glossary; no case data or security verdict"],
                    "forbidden_claims": case["forbidden_claims"]
                    if case
                    else ["No claim about this host or policy changes"],
                    "rubric": case["rubric"]
                    if case
                    else ["Useful general definition; no executable advice or invented host facts"],
                }
            )
    manifest = {
        "packet_version": PACKET_VERSION,
        "synthetic_only": True,
        "catalog_version": catalog["catalog_version"],
        "catalog_sha256": hashlib.sha256(catalog_raw).hexdigest(),
        "prompt_version": PROMPT_VERSION,
        "prompt_sha256": hashlib.sha256(prompt().encode("utf-8")).hexdigest(),
        "response_schema_version": catalog["response_schema_version"],
        "response_schema_sha256": hashlib.sha256(encode(response_schema())).hexdigest(),
        "approval_status": "not_approved",
        "approval_ready": False,
        "proposed_attempts": len(rows),
        "per_provider_attempts": 13,
        "output_token_limit_per_attempt": OUTPUT_LIMIT,
        "maximum_request_body_bytes": max(len(body) for body in files.values()),
        "input_token_allowance": None,
        "maximum_approved_spend_usd": None,
        "owner_paid_testing_limit_usd": 0,
        "owner_cost_direction": "Use legitimate free-tier access only; no paid test spending authorized. Account/model/free-credit eligibility remains unverified; exact A07 is not approved.",
        "credential_method": "pending owner choice; masked local entry only; never chat, argv, fixtures or logs",
        "retry_policy": "no automatic retries/fallback; timeout can still be billed; any repeat consumes a separately scoped attempt",
        "missing_before_A07_request": [
            "Review exact live runner and source hash; it is not implemented by this preparer",
            "Confirm account/model access, tier/data terms and current pricing; no account query authorized",
            "Approve input-token allowance, maximum spend and enforcement/stop method; body bytes are not token counts",
            "Select local masked credential mechanism; no key is requested or loaded here",
            "Bind exact candidate ZIP/source for three actual packaged GUI smokes and native network attribution",
            "Identify human factual reviewer and actual evidence retention/cleanup plan",
        ],
        "requests": rows,
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    return files


def check_packet(directory: Path, expected: dict[str, bytes]) -> None:
    check_plain_path(directory)
    if {path.name for path in directory.iterdir()} != set(expected):
        raise ValueError("Packet file set is incomplete or unexpected")
    held = OpenedDirectory(directory)
    try:
        for name, body in expected.items():
            with held.open_relative(name) as stream:
                if stream.read(len(body) + 1) != body:
                    raise ValueError("Packet bytes differ from current serializers/catalog")
    finally:
        held.close()


def write_packet(directory: Path, expected: dict[str, bytes]) -> None:
    check_plain_path(directory.parent)
    directory.mkdir()  # Never overwrite or merge an earlier approval artifact.
    marker = directory / ".incomplete"
    marker.write_text("Synthetic preparation unfinished; no approval authority\n", encoding="utf-8")
    for name, body in expected.items():
        with (directory / name).open("xb") as stream:
            stream.write(body)
    marker.unlink()
    check_packet(directory, expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = args.out.absolute()
    directory.relative_to(ROOT / "docs/ai/live-fixtures")
    files = packet_files((ROOT / "tests/fixtures/ai/evaluation-v1.json").read_bytes())
    if args.check:
        check_packet(directory, files)
    else:
        write_packet(directory, files)
    print(
        json.dumps(
            {
                "synthetic_request_files": len(files) - 1,
                "attempts_executed": 0,
                "A07": "not approved; prerequisites blocked",
                "packet": str(directory.relative_to(ROOT)),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
