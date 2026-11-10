"""Pure comparison of actual captured fields and evidence availability."""

import json
from collections import Counter
from typing import Literal

from wfdiag.contracts.comparison import Comparison, FindingCount, ProfileChange, RuleChange
from wfdiag.contracts.enums import Category, Completeness, Relevance
from wfdiag.contracts.models import Analysis, Event, Rule


def _counts(analysis: Analysis) -> tuple[FindingCount, ...]:
    counts = Counter((f.category, f.relevance) for f in analysis.findings)
    return tuple(
        FindingCount(category=category, relevance=relevance, count=count)
        for (category, relevance), count in sorted(counts.items())
    )


def _flow(event: Event) -> tuple[object, ...]:
    return (
        event.application_canonical,
        event.direction,
        event.protocol,
        event.source_address,
        event.source_port,
        event.destination_address,
        event.destination_port,
        event.interface_index,
        event.filter_origin,
    )


def _observations(analysis: Analysis) -> Counter[str]:
    return Counter(
        json.dumps(
            (
                f.category,
                f.evidence_grade,
                f.relevance,
                _flow(f.event) if f.event is not None else None,
                f.proposal_eligible,
                f.refusal_codes,
            ),
            sort_keys=True,
        )
        for f in analysis.findings
        if f.category not in (Category.EVIDENCE_GAP, Category.NO_RELEVANT_EVENT)
    )


def _rule_content(rule: Rule) -> dict[str, object]:
    return rule.model_dump(mode="json", exclude={"snapshot_utc", "source_ref"})


def compare_analyses(before: Analysis, after: Analysis) -> Comparison:
    warnings = []
    if before.intent != after.intent:
        warnings.append("INTENTS_DIFFER")
    if before.engine_version != after.engine_version:
        warnings.append("ENGINE_VERSIONS_DIFFER")
    if after.analyzed_at_utc < before.analyzed_at_utc:
        warnings.append("AFTER_ANALYSIS_PRECEDES_BEFORE")
    if before.completeness != Completeness.COMPLETE or after.completeness != Completeness.COMPLETE:
        warnings.append("INCOMPLETE_REQUIRED_EVIDENCE")
    change: Literal["changed", "unchanged", "not_observed", "unknown"] = "unknown"
    if not warnings:
        relevant_before = any(f.relevance == Relevance.RELEVANT for f in before.findings)
        relevant_after = any(f.relevance == Relevance.RELEVANT for f in after.findings)
        change = (
            "not_observed"
            if relevant_before and not relevant_after
            else "unchanged"
            if _observations(before) == _observations(after)
            else "changed"
        )
    available = (
        before.policy_rules is not None
        and after.policy_rules is not None
        and before.profiles is not None
        and after.profiles is not None
    )
    rule_changes = []
    profile_changes = []
    if available:
        old_rules = {r.rule_id.casefold(): r for r in before.policy_rules or ()}
        new_rules = {r.rule_id.casefold(): r for r in after.policy_rules or ()}
        for key in sorted(old_rules.keys() | new_rules.keys()):
            old, new = old_rules.get(key), new_rules.get(key)
            old_data, new_data = (
                _rule_content(old) if old else {},
                _rule_content(new) if new else {},
            )
            fields = tuple(
                name
                for name in sorted(old_data.keys() | new_data.keys())
                if old_data.get(name) != new_data.get(name)
            )
            if fields:
                actual = new if new is not None else old
                assert actual is not None
                rule_changes.append(
                    RuleChange(
                        rule_id=actual.rule_id,
                        change="added" if old is None else "removed" if new is None else "changed",
                        changed_fields=fields,
                        before=old,
                        after=new,
                    )
                )
        old_profiles = {p.profile: p for p in before.profiles or ()}
        new_profiles = {p.profile: p for p in after.profiles or ()}
        for profile in sorted(old_profiles.keys() | new_profiles.keys()):
            old_profile, new_profile = old_profiles.get(profile), new_profiles.get(profile)
            if (old_profile.model_dump(exclude={"source_ref"}) if old_profile else None) != (
                new_profile.model_dump(exclude={"source_ref"}) if new_profile else None
            ):
                profile_changes.append(
                    ProfileChange(profile=profile, before=old_profile, after=new_profile)
                )
    else:
        warnings.append("POLICY_CONTEXT_UNAVAILABLE")
    return Comparison(
        before_run_id=before.run_id,
        after_run_id=after.run_id,
        before_analyzed_at_utc=before.analyzed_at_utc,
        after_analyzed_at_utc=after.analyzed_at_utc,
        before_completeness=before.completeness,
        after_completeness=after.completeness,
        before_sources=before.sources,
        after_sources=after.sources,
        before_counts=_counts(before),
        after_counts=_counts(after),
        observation_change=change,
        policy_comparison="available" if available else "unavailable",
        rule_changes=tuple(rule_changes),
        profile_changes=tuple(profile_changes),
        warnings=tuple(warnings),
    )
