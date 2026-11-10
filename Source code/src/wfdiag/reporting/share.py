"""Build a minimal share derivative. No raw free text or reverse map is exported."""

import secrets
from collections.abc import Iterator
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field

from wfdiag.contracts.base import Contract, actual_boolean
from wfdiag.contracts.enums import (
    Category,
    Completeness,
    EvidenceGrade,
    NextStep,
    Relevance,
    SourceState,
)
from wfdiag.contracts.models import Analysis, SourceName
from wfdiag.services.cancellation import CancellationToken

REFUSAL_CODES = frozenset(
    {
        "UNSUPPORTED_OR_UNKNOWN_CAPTURE_PLATFORM",
        "INCOMPLETE_CAPTURE",
        "CAPTURE_TRUNCATED",
        "EVENT_WINDOW_UNKNOWN_OR_CONFLICTING",
        "STALE_OR_UNKNOWN_POLICY_SNAPSHOT",
        "POLICY_WINDOW_UNKNOWN_OR_CONFLICTING",
        "INCONSISTENT_RULE_SNAPSHOT",
        "POLICY_CHANGED",
        "POLICY_CONTINUITY_UNKNOWN",
        "INCOMPLETE_REQUIRED_EVIDENCE",
        "INTERFACE_CONTEXT_UNVERIFIED",
        "NETWORK_CONTEXT_INCOMPLETE_OR_STALE",
        "LOCAL_INTERFACE_ADDRESS_UNVERIFIED",
        "UNHANDLED_EVENT_CONTEXT",
        "INTENT_NOT_CONFIRMED_RELEVANT",
        "APPLICATION_IDENTITY_NOT_CONFIRMED",
        "UNRESOLVED_APPLICATION_PATH",
        "SHARED_APPLICATION_HOST",
        "UNSUPPORTED_OR_UNKNOWN_FLOW",
        "PACKET_EVENT_ONLY",
        "UNVERIFIED_EVENT_SCHEMA",
        "INCOMPLETE_ENDPOINTS",
        "UNKNOWN_OR_DISABLED_ACTIVE_PROFILE",
        "INTENDED_PROFILE_NOT_ACTIVE",
        "LOCAL_MERGE_NOT_CONFIRMED",
        "PROFILE_POLICY_OWNER_UNVERIFIED_OR_MANAGED",
        "UNHANDLED_POLICY_CONDITION",
        "EXTERNAL_OR_UNKNOWN_POLICY_OWNER",
        "CONFLICTING_BLOCK_IN_INTENDED_SCOPE",
        "INTENDED_SCOPE_POLICY_UNRESOLVED",
        "FINDING_REFERENCE_BUDGET",
        "CONTRADICTORY_OR_UNHANDLED_FILTER_ORIGIN",
        "UNRESOLVED_FILTER_ORIGIN",
        "ALLOW_POLICY_CONTRADICTS_BLOCK_EVENT",
        "DEFAULT_BLOCK_NOT_ESTABLISHED",
        *(c.value for c in Category),
    }
)


class ShareSource(Contract):
    source: SourceName
    state: SourceState
    warnings_present: bool


class ShareFinding(Contract):
    finding_alias: Annotated[str, Field(pattern=r"^F[0-9a-f]{16}$")]
    category: Category
    evidence_grade: EvidenceGrade
    relevance: Relevance
    proposal_eligible: bool
    evidence_aliases: Annotated[tuple[str, ...], Field(max_length=100)]
    refusal_codes: Annotated[tuple[str, ...], Field(max_length=50)]
    next_steps: tuple[NextStep, ...]


class ShareReport(Contract):
    schema_version: Literal["1.0"] = "1.0"
    mode: Literal["share"] = "share"
    report_id: Annotated[str, Field(pattern=r"^R[0-9a-f]{32}$")]
    review_required: Annotated[Literal[True], BeforeValidator(actual_boolean)] = True
    completeness: Completeness
    sources: tuple[ShareSource, ...]
    findings: Annotated[tuple[ShareFinding, ...], Field(max_length=100002)]
    excluded: tuple[str, ...] = (
        "Raw evidence",
        "Full paths, application and machine identity",
        "Exact addresses and timestamps",
        "Rule identities and source references",
        "Operator purpose and all other free text",
        "Reverse pseudonym map",
    )


def share_report_parts(
    analysis: Analysis, cancellation: CancellationToken | None = None
) -> tuple[ShareReport, Iterator[ShareFinding]]:
    """One allowlist/pseudonym implementation for buffered and streaming consumers."""
    token = cancellation or CancellationToken()
    token.check()
    reverse: dict[str, str] = {}

    def alias(value: str, prefix: str) -> str:
        key = prefix + "\0" + value
        if key not in reverse:
            reverse[key] = prefix + secrets.token_hex(8)
        return reverse[key]

    def findings() -> Iterator[ShareFinding]:
        for f in analysis.findings:
            token.check()
            yield ShareFinding(
                finding_alias=alias(f.finding_id, "F"),
                category=f.category,
                evidence_grade=f.evidence_grade,
                relevance=f.relevance,
                proposal_eligible=f.proposal_eligible,
                evidence_aliases=tuple(alias(ref, "E") for ref in f.evidence_refs),
                refusal_codes=tuple(
                    dict.fromkeys(
                        code if code in REFUSAL_CODES else "ADDITIONAL_RESTRICTION"
                        for code in f.refusal_codes
                    )
                ),
                next_steps=f.next_steps,
            )

    header = ShareReport(
        report_id="R" + secrets.token_hex(16),
        completeness=analysis.completeness,
        sources=tuple(
            ShareSource(source=s.source, state=s.state, warnings_present=bool(s.warnings))
            for s in analysis.sources
        ),
        findings=(),
    )
    return header, findings()


def make_share_report(analysis: Analysis) -> ShareReport:
    header, findings = share_report_parts(analysis)
    return ShareReport.model_validate(
        {
            **{name: getattr(header, name) for name in ShareReport.model_fields},
            "findings": tuple(findings),
        },
        strict=True,
    )
