"""Captured before/after facts, without a repair or security verdict."""

from typing import Annotated, Literal

from pydantic import Field

from wfdiag.contracts.base import Contract, Identifier, RuleIdentifier
from wfdiag.contracts.enums import Category, Completeness, Profile, Relevance
from wfdiag.contracts.models import UTC, FirewallProfile, Rule, SourceStatus


class FindingCount(Contract):
    category: Category
    relevance: Relevance
    count: Annotated[int, Field(ge=0, le=100002)]


class RuleChange(Contract):
    rule_id: RuleIdentifier
    change: Literal["added", "removed", "changed"]
    changed_fields: tuple[Identifier, ...]
    before: Rule | None
    after: Rule | None


class ProfileChange(Contract):
    profile: Profile
    before: FirewallProfile | None
    after: FirewallProfile | None


class Comparison(Contract):
    schema_version: Literal["1.0"] = "1.0"
    before_run_id: Identifier
    after_run_id: Identifier
    before_analyzed_at_utc: UTC
    after_analyzed_at_utc: UTC
    before_completeness: Completeness
    after_completeness: Completeness
    before_sources: tuple[SourceStatus, ...]
    after_sources: tuple[SourceStatus, ...]
    before_counts: Annotated[tuple[FindingCount, ...], Field(max_length=21)]
    after_counts: Annotated[tuple[FindingCount, ...], Field(max_length=21)]
    observation_change: Literal["changed", "unchanged", "not_observed", "unknown"]
    policy_comparison: Literal["available", "unavailable"]
    rule_changes: Annotated[tuple[RuleChange, ...], Field(max_length=20000)]
    profile_changes: Annotated[tuple[ProfileChange, ...], Field(max_length=3)]
    warnings: tuple[Identifier, ...]
    repair_status: Literal["not_established"] = "not_established"
    conclusion: Literal[
        "This compares captured observations and policy. A later absence of relevant events does not prove repair."
    ] = "This compares captured observations and policy. A later absence of relevant events does not prove repair."
