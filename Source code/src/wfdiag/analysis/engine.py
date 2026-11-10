"""Evidence-driven classifications over validated records; pure and independent of AI/Qt."""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import PureWindowsPath
from typing import Protocol

from wfdiag.analysis.matching import Match, flow_endpoints, match_rule, relevance, scope_overlap
from wfdiag.contracts.enums import (
    Category,
    Completeness,
    Direction,
    EvidenceGrade,
    NextStep,
    Profile,
    Relevance,
    SourceState,
)
from wfdiag.contracts.models import (
    Analysis,
    Event,
    Finding,
    FirewallProfile,
    Host,
    Intent,
    Manifest,
    NetworkSnapshot,
    Rule,
    SourceStatus,
    TextLogResult,
)
from wfdiag.contracts.platform import desktop_target_eligible
from wfdiag.parsers.deduplication import EventGroup, iter_event_groups
from wfdiag.services.cancellation import CancellationToken
from wfdiag.version import __version__

FRESHNESS = timedelta(seconds=120)
REQUIRED = {"host", "profiles", "rules", "events", "collection-errors"}
SHARED_HOSTS = frozenset(
    {
        "svchost.exe",
        "dllhost.exe",
        "rundll32.exe",
        "wscript.exe",
        "cscript.exe",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "python.exe",
        "pythonw.exe",
        "java.exe",
        "javaw.exe",
        "dotnet.exe",
        "node.exe",
        "mshta.exe",
        "wsl.exe",
    }
)


class DiagnosisContext(Protocol):
    @property
    def host(self) -> Host | None: ...

    @property
    def policy_snapshot_utc(self) -> datetime | None: ...

    @property
    def policy_change_observed(self) -> bool | None: ...

    @property
    def completeness(self) -> Completeness: ...

    @property
    def sources(self) -> tuple[SourceStatus, ...]: ...


@dataclass(frozen=True)
class DerivedContext:
    host: Host | None
    policy_snapshot_utc: datetime | None
    policy_change_observed: bool | None
    completeness: Completeness
    sources: tuple[SourceStatus, ...]


def _event_profile(
    event: Event, profiles: tuple[FirewallProfile, ...], network: NetworkSnapshot | None
) -> Profile | None:
    if network is not None and event.interface_index is not None:
        matches = tuple(i for i in network.interfaces if i.interface_index == event.interface_index)
        if len(matches) == 1 and matches[0].state == "up":
            return matches[0].active_profile
        return None
    active = tuple(p.profile for p in profiles if p.active is True)
    return active[0] if len(active) == 1 else None


def _timing(event: Event, manifest: DiagnosisContext, rules: tuple[Rule, ...]) -> tuple[str, ...]:
    reasons = []
    snapshot = manifest.policy_snapshot_utc
    sources = {s.source: s for s in manifest.sources}
    events = sources["events"]
    if (
        events.window_start_utc is None
        or events.window_end_utc is None
        or not events.window_start_utc <= event.timestamp_utc <= events.window_end_utc
    ):
        reasons.append("EVENT_WINDOW_UNKNOWN_OR_CONFLICTING")
    if snapshot is None or abs(snapshot - event.timestamp_utc) > FRESHNESS:
        reasons.append("STALE_OR_UNKNOWN_POLICY_SNAPSHOT")
    if snapshot is not None:
        for name in ("profiles", "rules"):
            source = sources[name]
            if (
                source.window_start_utc is None
                or source.window_end_utc is None
                or not source.window_start_utc <= snapshot <= source.window_end_utc
            ):
                reasons.append("POLICY_WINDOW_UNKNOWN_OR_CONFLICTING")
                break
        if any(r.snapshot_utc != snapshot for r in rules):
            reasons.append("INCONSISTENT_RULE_SNAPSHOT")
    if manifest.policy_change_observed is True:
        reasons.append("POLICY_CHANGED")
    elif manifest.policy_change_observed is None:
        reasons.append("POLICY_CONTINUITY_UNKNOWN")
    return tuple(reasons)


def _identifier(event: Event) -> str:
    data = json.dumps(
        event.model_dump(mode="json", exclude={"source_ref"}), sort_keys=True, separators=(",", ":")
    )
    return "F" + hashlib.sha256(data.encode()).hexdigest()


def evaluate_event(
    group: EventGroup,
    manifest: DiagnosisContext,
    profiles: tuple[FirewallProfile, ...],
    rules: tuple[Rule, ...],
    intent: Intent | None,
    network: NetworkSnapshot | None,
) -> Finding:
    event = group.event
    relation = relevance(event, intent)
    profile_name = _event_profile(event, profiles, network)
    profile = next((p for p in profiles if p.profile == profile_name), None)
    matches = tuple(match_rule(event, rule, profile_name) for rule in rules)
    full = tuple(m.rule for m in matches if m.result == Match.YES)
    possible = tuple(m.rule for m in matches if m.result == Match.UNKNOWN)
    mismatch = tuple(
        m.rule for m in matches if m.profile_only_mismatch and m.rule.action == "Allow"
    )
    blocking = tuple(r for r in full if r.action == "Block")
    allowing = tuple(r for r in full if r.action == "Allow")
    direct = tuple(
        r
        for r in rules
        if event.filter_origin is not None
        and event.filter_origin.casefold() == r.rule_id.casefold()
    )
    time_reasons = _timing(event, manifest, rules)
    refusals: list[str] = list(time_reasons)
    limitations = [
        "Current policy is not event-time proof.",
        "Candidate matches do not prove filter origin.",
    ]
    if network is None:
        limitations.append(
            "Interface-specific network context was not captured; a single current active profile is used only as a candidate context."
        )
    complete = manifest.completeness == Completeness.COMPLETE and all(
        s.state in (SourceState.COMPLETE, SourceState.EMPTY)
        for s in manifest.sources
        if s.source in REQUIRED
    )
    if not complete:
        refusals.append("INCOMPLETE_CAPTURE")
    if any(
        s.state not in (SourceState.COMPLETE, SourceState.EMPTY)
        for s in manifest.sources
        if s.source in REQUIRED
    ):
        refusals.append("INCOMPLETE_REQUIRED_EVIDENCE")
    if any(s.state == SourceState.TRUNCATED for s in manifest.sources):
        refusals.append("CAPTURE_TRUNCATED")
    if not desktop_target_eligible(manifest.host):
        refusals.append("UNSUPPORTED_OR_UNKNOWN_CAPTURE_PLATFORM")
    if network is None or event.interface_index is None:
        refusals.append("INTERFACE_CONTEXT_UNVERIFIED")
    else:
        source = next((s for s in manifest.sources if s.source == "network"), None)
        if (
            source is None
            or source.state != SourceState.COMPLETE
            or abs(network.observed_at_utc - event.timestamp_utc) > FRESHNESS
        ):
            refusals.append("NETWORK_CONTEXT_INCOMPLETE_OR_STALE")
        local, _, _, _ = flow_endpoints(event)
        interface = next(
            (i for i in network.interfaces if i.interface_index == event.interface_index), None
        )
        if interface is None or local not in interface.addresses:
            refusals.append("LOCAL_INTERFACE_ADDRESS_UNVERIFIED")
    if any(key != "system_time_raw" for key in event.unknown_fields) or any(
        w
        not in {
            "SUBMICROSECOND_TIME_PRESERVED_AS_RAW",
            "PID_UNRESOLVED",
            "FILTER_ORIGIN_UNAVAILABLE",
            "FILTERRTID_UNRESOLVED",
        }
        for w in event.warnings
    ):
        refusals.append("UNHANDLED_EVENT_CONTEXT")
    if relation != Relevance.RELEVANT:
        refusals.append("INTENT_NOT_CONFIRMED_RELEVANT")
    if intent is None or not intent.application_identity_confirmed:
        refusals.append("APPLICATION_IDENTITY_NOT_CONFIRMED")
    if event.application_canonical is None:
        refusals.append("UNRESOLVED_APPLICATION_PATH")
    elif PureWindowsPath(event.application_canonical).name.casefold() in SHARED_HOSTS:
        refusals.append("SHARED_APPLICATION_HOST")
    if event.protocol != 6 or event.direction == Direction.UNKNOWN:
        refusals.append("UNSUPPORTED_OR_UNKNOWN_FLOW")
    if event.event_id != 5157:
        refusals.append("PACKET_EVENT_ONLY")
    if event.provider != "Microsoft-Windows-Security-Auditing" or event.event_version not in (0, 1):
        refusals.append("UNVERIFIED_EVENT_SCHEMA")
    local_address, local_port, remote_address, remote_port = flow_endpoints(event)
    if None in (local_address, local_port, remote_address, remote_port):
        refusals.append("INCOMPLETE_ENDPOINTS")
    if profile is None or profile.enabled is not True or profile.active is not True:
        refusals.append("UNKNOWN_OR_DISABLED_ACTIVE_PROFILE")
    if intent is not None and profile_name != intent.profile:
        refusals.append("INTENDED_PROFILE_NOT_ACTIVE")
    if profile is None or profile.allow_local_rule_merge is not True:
        refusals.append("LOCAL_MERGE_NOT_CONFIRMED")
    if profile is None or profile.policy_source_type != "local" or not profile.policy_source:
        refusals.append("PROFILE_POLICY_OWNER_UNVERIFIED_OR_MANAGED")
    if possible or any(r.action == "unknown" for r in full):
        refusals.append("UNHANDLED_POLICY_CONDITION")
    if any(
        r.policy_source_type != "local" or not r.policy_source
        for r in (*full, *possible, *mismatch, *direct)
    ):
        refusals.append("EXTERNAL_OR_UNKNOWN_POLICY_OWNER")
    if intent is not None:
        scoped = tuple((r, scope_overlap(intent, r)) for r in rules)
        if any(r.action == "Block" and overlap != Match.NO for r, overlap in scoped):
            refusals.append("CONFLICTING_BLOCK_IN_INTENDED_SCOPE")
        if any(
            overlap == Match.UNKNOWN
            or (
                overlap == Match.YES
                and (
                    r.action == "unknown" or r.policy_source_type != "local" or not r.policy_source
                )
            )
            for r, overlap in scoped
        ):
            refusals.append("INTENDED_SCOPE_POLICY_UNRESOLVED")
    if len(group.source_refs) > 90 or len(full) + len(possible) + len(mismatch) > 100:
        refusals.append("FINDING_REFERENCE_BUDGET")
        limitations.append(
            "The displayed references or candidate list is capped; review the complete private source."
        )
    category = Category.UNRESOLVED_WFP_BLOCK
    grade = EvidenceGrade.UNKNOWN
    summary = "Blocked event; policy attribution is unresolved"
    selected = (*full, *possible, *mismatch)
    if direct:
        selected = (*selected, *direct)
        matched_direct = (
            tuple(r for r in blocking if r.rule_id.casefold() == event.filter_origin.casefold())
            if event.filter_origin
            else ()
        )
        if len(direct) == 1 and matched_direct:
            category, summary = (
                Category.EXPLICIT_BLOCK,
                "Filter Origin resolves to an explicit block candidate",
            )
            grade = EvidenceGrade.CONFIRMED if not time_reasons else EvidenceGrade.SUPPORTED
        else:
            refusals.append("CONTRADICTORY_OR_UNHANDLED_FILTER_ORIGIN")
    elif event.filter_origin:
        refusals.append("UNRESOLVED_FILTER_ORIGIN")
        limitations.append(
            "The supplied origin is not a captured stable rule ID; default/third-party origins are not guessed."
        )
    elif blocking:
        category, grade, summary = (
            Category.EXPLICIT_BLOCK,
            EvidenceGrade.SUPPORTED,
            "Current explicit block candidates match the observed flow",
        )
    elif profile is not None and profile.allow_local_rule_merge is False:
        category, grade, summary = (
            Category.LOCAL_RULE_MERGE_RESTRICTED,
            EvidenceGrade.SUPPORTED,
            "Local rule merging is disabled for the candidate active profile",
        )
    elif mismatch:
        category, grade, summary = (
            Category.PROFILE_MISMATCH,
            EvidenceGrade.SUPPORTED,
            "Allow candidates cover other profiles",
        )
    elif allowing:
        refusals.append("ALLOW_POLICY_CONTRADICTS_BLOCK_EVENT")
    elif (
        not possible
        and profile is not None
        and profile.enabled is True
        and profile.active is True
        and (
            profile.default_inbound
            if event.direction == Direction.INBOUND
            else profile.default_outbound
            if event.direction == Direction.OUTBOUND
            else "unknown"
        )
        == "Block"
    ):
        category, grade, summary = (
            Category.DEFAULT_BLOCK,
            EvidenceGrade.SUPPORTED,
            "Possible default block",
        )
    else:
        refusals.append("DEFAULT_BLOCK_NOT_ESTABLISHED")
    if "UNVERIFIED_EVENT_SCHEMA" in refusals:
        category, grade, summary = (
            Category.EVIDENCE_GAP,
            EvidenceGrade.UNKNOWN,
            "Event provider or version is not supported for attribution",
        )
    if category != Category.DEFAULT_BLOCK:
        refusals.append(category.value)
    if time_reasons:
        limitations.append(
            "Policy timing or continuity is uncertain or conflicting; no proposal is permitted."
        )
    if not complete:
        limitations.append("Required source evidence is incomplete.")
    if category == Category.EXPLICIT_BLOCK:
        limitations.append(
            "An additional allow rule does not override a conflicting explicit block."
        )
    refs = list(group.source_refs[:90])
    refs.extend(r.source_ref for r in selected[:5])
    if profile is not None:
        refs.append(profile.source_ref)
    candidates = tuple(dict.fromkeys(r.rule_id for r in selected))[:100]
    return Finding(
        finding_id=_identifier(event),
        category=category,
        evidence_grade=grade,
        summary=summary,
        observation=f"Blocked event {event.event_id}/{event.record_id} at {event.timestamp_utc.isoformat()}; rule candidates: {len(full)} complete, {len(possible)} incomplete.",
        evidence_refs=tuple(dict.fromkeys(refs))[:100],
        candidate_rules=candidates,
        policy_snapshot_utc=manifest.policy_snapshot_utc,
        relevance=relation,
        limitations=tuple(limitations),
        alternative_explanations=(
            "Policy may have changed.",
            "Unresolved WFP, service, IPsec or app context.",
        ),
        next_steps=(NextStep.REVIEW_POLICY_OWNER, NextStep.REVIEW_WINDOW, NextStep.VERIFY_INTENT),
        proposal_eligible=not refusals,
        refusal_codes=tuple(dict.fromkeys(refusals)),
        event=event,
        event_refs=group.source_refs[:90],
    )


def analyze_case(
    manifest: Manifest,
    profiles: tuple[FirewallProfile, ...],
    rules: tuple[Rule, ...],
    events: Iterable[Event],
    *,
    intent: Intent | None,
    network: NetworkSnapshot | None,
    analyzed_at_utc: datetime,
    cancellation: CancellationToken | None = None,
    firewall_log: TextLogResult | None = None,
) -> Analysis:
    token = cancellation or CancellationToken()
    ordered_rules = tuple(sorted(rules, key=lambda r: r.rule_id.casefold()))
    findings: list[Finding] = []
    sources = manifest.sources
    if firewall_log is not None:
        if not any(s.source == "firewall-log" for s in sources):
            raise ValueError("Text observations require a declared source")
        sources = tuple(
            SourceStatus(
                source=s.source,
                state=SourceState.TRUNCATED
                if firewall_log.truncated
                else SourceState.ERROR
                if firewall_log.rejected or len(firewall_log.observations) != s.records
                else s.state,
                window_start_utc=s.window_start_utc,
                window_end_utc=s.window_end_utc,
                records=len(firewall_log.observations),
                warnings=(*s.warnings[:98], "OPTIONAL_TEXT_RECORDS_REJECTED_OR_COUNT_MISMATCH")
                if firewall_log.rejected or len(firewall_log.observations) != s.records
                else s.warnings,
            )
            if s.source == "firewall-log"
            else s
            for s in sources
        )
    incomplete = manifest.completeness != Completeness.COMPLETE or any(
        s.state == SourceState.TRUNCATED
        or (s.source in REQUIRED and s.state not in (SourceState.COMPLETE, SourceState.EMPTY))
        for s in sources
    )
    context = DerivedContext(
        manifest.host,
        manifest.policy_snapshot_utc,
        manifest.policy_change_observed,
        Completeness.INCOMPLETE if incomplete else Completeness.COMPLETE,
        sources,
    )

    def checked_events() -> Iterable[Event]:
        count = 0
        for event in events:
            token.check()
            count += 1
            if count > 100000:
                raise ValueError("Event count budget exceeded")
            yield event
        expected = next(s.records for s in manifest.sources if s.source == "events")
        if count != expected:
            raise ValueError("Event source count is inconsistent")

    for group in iter_event_groups(checked_events()):
        token.check()
        if len(findings) >= 100000:
            raise ValueError("Finding count budget exceeded; narrow the approved capture window")
        findings.append(evaluate_event(group, context, profiles, ordered_rules, intent, network))
    if incomplete:
        findings.append(
            Finding(
                finding_id="GAP-REQUIRED-SOURCES",
                category=Category.EVIDENCE_GAP,
                evidence_grade=EvidenceGrade.UNKNOWN,
                summary="Captured evidence is incomplete",
                observation="Required sources are unavailable or captured evidence is truncated. An empty or missing event set cannot establish that no firewall block occurred.",
                evidence_refs=(),
                policy_snapshot_utc=manifest.policy_snapshot_utc,
                relevance=Relevance.UNKNOWN,
                next_steps=(NextStep.COLLECT_APPROVED_EVIDENCE, NextStep.GLOSSARY_AUDITING),
                proposal_eligible=False,
                refusal_codes=("INCOMPLETE_CAPTURE",),
            )
        )
    event_log_read = any(
        s.source == "events" and s.state in (SourceState.COMPLETE, SourceState.EMPTY)
        for s in sources
    )
    if event_log_read and (
        not findings
        or (intent is not None and not any(f.relevance == Relevance.RELEVANT for f in findings))
    ):
        findings.append(
            Finding(
                finding_id="NO-RELEVANT-EVENT",
                category=Category.NO_RELEVANT_EVENT,
                evidence_grade=EvidenceGrade.UNKNOWN,
                summary="No confirmed relevant event was identified",
                observation="No observed event was established as relevant to the supplied intent. This does not show that the firewall or network is healthy.",
                evidence_refs=(),
                policy_snapshot_utc=manifest.policy_snapshot_utc,
                relevance=Relevance.UNKNOWN,
                next_steps=(
                    NextStep.VERIFY_INTENT,
                    NextStep.REVIEW_WINDOW,
                    NextStep.GLOSSARY_AUDITING,
                ),
                proposal_eligible=False,
                refusal_codes=("NO_RELEVANT_EVENT",),
            )
        )
    return Analysis(
        run_id=manifest.run_id,
        engine_version=__version__,
        analyzed_at_utc=analyzed_at_utc,
        completeness=Completeness.INCOMPLETE if incomplete else Completeness.COMPLETE,
        sources=sources,
        findings=tuple(findings),
        intent=intent,
        host=manifest.host,
        collected_at_utc=manifest.collected_at_utc,
        policy_snapshot_utc=manifest.policy_snapshot_utc,
        policy_change_observed=manifest.policy_change_observed,
        profiles=profiles,
        policy_rules=ordered_rules,
        network=network,
        firewall_log=firewall_log,
    )
