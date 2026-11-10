"""Generate exact-scope administrator review data, never a firewall command."""

from pathlib import PureWindowsPath

from wfdiag.analysis.engine import SHARED_HOSTS, evaluate_event
from wfdiag.contracts.enums import Category, Completeness, EvidenceGrade, Relevance, SourceState
from wfdiag.contracts.models import Analysis, Intent, Proposal
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.parsers.deduplication import EventGroup
from wfdiag.version import __version__


class ProposalRefused(DiagnosticError):
    def __init__(self, codes: tuple[str, ...]) -> None:
        self.refusal_codes = tuple(dict.fromkeys(codes))
        super().__init__(
            ExitCode.INVALID_INPUT,
            "Proposal withheld. Review refusal codes in the private analysis and confirm the exact intended flow.",
        )


def generate_proposal(analysis: Analysis, finding_id: str, intent: Intent) -> Proposal:
    reasons = []
    if analysis.engine_version != __version__:
        reasons.append("ENGINE_VERSION_MISMATCH")
    if analysis.intent != intent:
        reasons.append("INTENT_DIFFERS_FROM_ANALYZED_FLOW")
    if not intent.application_identity_confirmed:
        reasons.append("APPLICATION_IDENTITY_NOT_CONFIRMED")
    if PureWindowsPath(intent.application_path).name.casefold() in SHARED_HOSTS:
        reasons.append("SHARED_APPLICATION_HOST")
    if analysis.completeness != Completeness.COMPLETE or any(
        s.state not in (SourceState.COMPLETE, SourceState.EMPTY)
        for s in analysis.sources
        if s.source in {"host", "profiles", "rules", "events", "collection-errors"}
    ):
        reasons.append("INCOMPLETE_REQUIRED_EVIDENCE")
    finding = next((f for f in analysis.findings if f.finding_id == finding_id), None)
    if finding is None:
        raise ProposalRefused((*reasons, "FINDING_NOT_FOUND"))
    if (
        finding.category != Category.DEFAULT_BLOCK
        or finding.evidence_grade == EvidenceGrade.UNKNOWN
        or finding.relevance != Relevance.RELEVANT
        or not finding.evidence_refs
    ):
        reasons.append("SUPPORTED_RELEVANT_DEFAULT_BLOCK_REQUIRED")
    reasons.extend(finding.refusal_codes)
    if not finding.proposal_eligible:
        reasons.append("FINDING_NOT_ELIGIBLE")
    if (
        finding.event is None
        or not finding.event_refs
        or analysis.profiles is None
        or analysis.policy_rules is None
    ):
        reasons.append("DECISION_EVIDENCE_UNAVAILABLE")
    else:
        verified = evaluate_event(
            EventGroup(finding.event, finding.event_refs),
            analysis,
            analysis.profiles,
            analysis.policy_rules,
            intent,
            analysis.network,
        )
        if verified.finding_id != finding.finding_id or not verified.proposal_eligible:
            reasons.extend(verified.refusal_codes)
            reasons.append("ELIGIBILITY_RECHECK_FAILED")
    if any(
        f.category == Category.EXPLICIT_BLOCK and f.relevance != Relevance.UNRELATED
        for f in analysis.findings
    ):
        reasons.append("CONFLICTING_EXPLICIT_BLOCK_IN_CASE")
    if reasons:
        raise ProposalRefused(tuple(reasons))
    service_port = intent.local_port if intent.direction == "inbound" else intent.remote_port
    if service_port is None:
        raise ProposalRefused(("EXPECTED_SERVICE_PORT_REQUIRED",))
    return Proposal(
        finding_id=finding.finding_id,
        direction=intent.direction,
        program=intent.application_path,
        service_port=service_port,
        peer_scope=intent.remote_addresses,
        profile=intent.profile,
        evidence_refs=finding.evidence_refs,
        assumptions=(
            "Operator independently confirmed the exact desktop executable and business intent.",
            "Captured policy and source history support the bounded finding; review any later policy change.",
            "Peer scope and service port come from operator intent, not a guessed expansion of observed traffic.",
        ),
        review_steps=(
            "Verify application identity, owner authorization and expected peer scope again.",
            "Review the complete private evidence, source completeness, current effective policy and all refusal conditions.",
            "Confirm no conflicting block, managed restriction, service, IPsec or third-party filter requires a different policy owner.",
            "Submit through the administrator's normal change review; use an isolated controlled reproduction before any approved deployment.",
            "Review and document rollback separately. This artifact executes no changes.",
        ),
        change_request_description=f"Review a narrowly scoped TCP {intent.direction} allow exception for the independently verified application on the {intent.profile.value} profile, service port {service_port}, and exactly the listed peer scope. Purpose: {intent.purpose}",
    )
