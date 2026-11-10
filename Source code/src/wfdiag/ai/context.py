"""Construct AI data by allowlist. Free text and local identities never become context."""

import json
import secrets
from collections.abc import Iterable
from ipaddress import ip_address
from itertools import chain
from pathlib import PureWindowsPath

from wfdiag.ai.contracts import AiContext, AiRequest
from wfdiag.ai.policy import DisclosurePolicy, context_revision
from wfdiag.contracts.enums import NextStep, Relevance
from wfdiag.contracts.models import Analysis
from wfdiag.reporting.share import REFUSAL_CODES

GENERAL_QUESTIONS = {
    "profiles": ("What is a firewall profile?", NextStep.GLOSSARY_PROFILE),
    "auditing": ("Why can missing audit events limit a diagnosis?", NextStep.GLOSSARY_AUDITING),
}


class SessionAliases:
    def __init__(self) -> None:
        self._map: dict[tuple[str, str, str], str] = {}

    def reference(self, case_revision: str, local: str, prefix: str) -> str:
        key = case_revision, local, prefix
        if key not in self._map:
            if len(self._map) >= 1024:
                self._map.clear()
            self._map[key] = prefix + secrets.token_hex(8).upper()
        return self._map[key]

    def clear(self) -> None:
        self._map.clear()

    def local_reference(self, revision: str, alias: str) -> str | None:
        for (stored_revision, local, _), public in self._map.items():
            if stored_revision == revision and public == alias:
                return local
        return None

    def __repr__(self) -> str:
        return "SessionAliases(<private local references>)"


def general_request(question_id: str) -> AiRequest:
    question, step = GENERAL_QUESTIONS[question_id]
    return AiRequest(
        task_mode="general_help",
        question=question,
        approved_context=None,
        allowed_next_steps=(step,),
    )


def private_values(analysis: Analysis) -> Iterable[str]:
    yield analysis.run_id
    if analysis.host is not None and analysis.host.hostname:
        yield analysis.host.hostname
    if analysis.intent is not None:
        yield analysis.intent.application_path
        yield PureWindowsPath(analysis.intent.application_path).name
        yield analysis.intent.purpose
    for rule in analysis.policy_rules or ():
        yield rule.rule_id
        yield rule.display_name
        if rule.policy_source:
            yield rule.policy_source
    for finding in analysis.findings:
        yield finding.finding_id
        if finding.event is not None:
            for program in (finding.event.application_raw, finding.event.application_canonical):
                if program:
                    yield program
                    yield PureWindowsPath(program).name
            for key, value in finding.event.unknown_fields.items():
                if value and any(
                    s in key.casefold()
                    for s in ("user", "host", "account", "secret", "token", "password")
                ):
                    yield value


def selected_request(
    analysis: Analysis,
    finding_id: str,
    question: str,
    aliases: SessionAliases,
    *,
    selection_revision: str,
    extra_forbidden: Iterable[str] = (),
) -> tuple[AiRequest, str, DisclosurePolicy]:
    finding = next((f for f in analysis.findings if f.finding_id == finding_id), None)
    if finding is None:
        raise ValueError("Select a validated engine finding")
    policy = DisclosurePolicy(chain(private_values(analysis), extra_forbidden))
    policy.check_text(question, character_limit=1000)
    event = finding.event
    revision = context_revision(
        {
            "selection": selection_revision,
            "case": analysis.run_id,
            "engine": analysis.engine_version,
            "time": analysis.analyzed_at_utc.isoformat(),
            "completeness": analysis.completeness.value,
            "intent": analysis.intent.model_dump(mode="json") if analysis.intent else None,
            "finding": finding.model_dump(mode="json"),
        }
    )
    codes = tuple(
        dict.fromkeys(
            code if code in REFUSAL_CODES else "ADDITIONAL_RESTRICTION"
            for code in finding.refusal_codes
        )
    )
    if len(codes) > 20:
        codes = (*codes[:19], "ADDITIONAL_RESTRICTION")
    limitations = []
    if finding.limitations:
        limitations.append("LIMITATIONS_RECORDED")
    if finding.alternative_explanations:
        limitations.append("ALTERNATIVE_EXPLANATIONS_RECORDED")
    if len(finding.evidence_refs) > 5:
        limitations.append("OBSERVATIONS_LIMITED_TO_FIVE")
    port = None
    if (
        analysis.intent is not None
        and finding.relevance == Relevance.RELEVANT
        and event is not None
        and event.protocol == 6
        and event.direction.value == analysis.intent.direction
    ):
        port = (
            analysis.intent.local_port
            if analysis.intent.direction == "inbound"
            else analysis.intent.remote_port
        )
    family = "unknown"
    if event is not None and event.source_address is not None:
        family = "IPv4" if ip_address(event.source_address).version == 4 else "IPv6"
    context = AiContext.model_validate_json(
        json.dumps(
            {
                "finding_ref": aliases.reference(revision, finding.finding_id, "F"),
                "category": finding.category.value,
                "evidence_grade": finding.evidence_grade.value,
                "completeness": analysis.completeness.value,
                "relevance": finding.relevance.value,
                "proposal_eligible": finding.proposal_eligible,
                "refusal_codes": codes,
                "protocol": "TCP" if event is not None and event.protocol == 6 else None,
                "direction": event.direction.value if event is not None else "unknown",
                "address_family": family,
                "service_port": port,
                "observations": [
                    {
                        "reference": aliases.reference(revision, ref, "E"),
                        "code": "CAPTURED_EVIDENCE_REFERENCE",
                    }
                    for ref in finding.evidence_refs[:5]
                ],
                "limitation_codes": limitations,
                "allowed_next_steps": [step.value for step in finding.next_steps[:5]],
            }
        )
    )
    request = AiRequest(
        task_mode="selected_finding",
        question=question,
        approved_context=context,
        allowed_next_steps=context.allowed_next_steps,
    )
    policy.check_json(request.model_dump_json().encode())
    return request, revision, policy
