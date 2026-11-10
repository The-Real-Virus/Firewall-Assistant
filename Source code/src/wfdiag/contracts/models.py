"""Core evidence contracts. Models validate records, never infer a diagnosis."""

from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BeforeValidator, Field, model_validator

from wfdiag.contracts.base import (
    Contract,
    Identifier,
    NonExecutable,
    PathText,
    Port,
    RuleIdentifier,
    Sha256,
    ShortText,
    actual_integer,
    utc_only,
    windows_program,
)
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

UTC = Annotated[datetime, AfterValidator(utc_only)]
Program = Annotated[PathText, AfterValidator(windows_program)]
SchemaVersion = Literal["1.0"]
SourceName = Literal[
    "host", "profiles", "rules", "events", "collection-errors", "network", "firewall-log"
]
SourceFile = Literal[
    "host.json",
    "profiles.json",
    "rules.json",
    "events.ndjson",
    "collection-errors.json",
    "network.json",
    "firewall-log.txt",
]


def checked_address(value: str) -> str:
    if "%" in value:
        raise ValueError("A scoped address needs separately verified interface context")
    ip_address(value)
    return value


def checked_peer(value: str) -> str:
    network = ip_network(value, strict=True)
    if network.prefixlen == 0 or network.network_address.is_unspecified or network.is_multicast:
        raise ValueError("An explicit approved peer scope is required")
    return value


Address = Annotated[str, Field(min_length=2, max_length=64), AfterValidator(checked_address)]
Peer = Annotated[str, Field(min_length=2, max_length=80), AfterValidator(checked_peer)]


class SourceStatus(Contract):
    source: SourceName
    state: SourceState
    window_start_utc: UTC | None
    window_end_utc: UTC | None
    records: Annotated[int, Field(ge=0, le=100000)] = 0
    warnings: Annotated[tuple[ShortText, ...], Field(max_length=100)] = ()

    @model_validator(mode="after")
    def ordered_window(self) -> Self:
        if self.state == SourceState.EMPTY and self.records:
            raise ValueError("An empty source cannot contain records")
        if (self.window_start_utc is None) != (self.window_end_utc is None):
            raise ValueError("Both window bounds or neither must be supplied")
        if (
            self.window_start_utc
            and self.window_end_utc
            and self.window_end_utc < self.window_start_utc
        ):
            raise ValueError("Source window ends before it starts")
        return self


class ManifestFile(Contract):
    filename: SourceFile
    byte_length: Annotated[int, Field(ge=0, le=128 * 1024 * 1024)]
    sha256: Sha256


class Host(Contract):
    schema_version: SchemaVersion = "1.0"
    os: Literal["windows", "linux", "darwin", "unknown"]
    edition: ShortText | None
    build: ShortText | None
    architecture: Literal["x64", "arm64", "x86", "unknown"]
    supported_build: bool
    hostname: ShortText | None = None
    windows_product_type: Annotated[Literal[1, 2, 3], BeforeValidator(actual_integer)] | None = None


class Manifest(Contract):
    schema_version: SchemaVersion = "1.0"
    run_id: Identifier
    collector_version: Identifier
    collected_at_utc: UTC
    policy_snapshot_utc: UTC | None = None
    policy_change_observed: bool | None = None
    host: Host
    completeness: Completeness
    sources: Annotated[tuple[SourceStatus, ...], Field(min_length=5, max_length=7)]
    files: Annotated[tuple[ManifestFile, ...], Field(min_length=5, max_length=7)]

    @model_validator(mode="after")
    def coherent_sources(self) -> Self:
        files = {f.filename for f in self.files}
        required = {
            "host.json",
            "profiles.json",
            "rules.json",
            "events.ndjson",
            "collection-errors.json",
        }
        if not required.issubset(files) or len(files) != len(self.files):
            raise ValueError("Manifest needs distinct required source files")
        names = {s.source for s in self.sources}
        required_names = {"host", "profiles", "rules", "events", "collection-errors"}
        if not required_names.issubset(names) or len(names) != len(self.sources):
            raise ValueError("Manifest needs distinct required source statuses")
        filenames = {"events": "events.ndjson", "firewall-log": "firewall-log.txt"}
        if {filenames.get(name, name + ".json") for name in names} != files:
            raise ValueError("Source statuses must match the declared files")
        if sum(f.byte_length for f in self.files) > 256 * 1024 * 1024:
            raise ValueError("Case exceeds total input budget")
        if self.completeness == Completeness.COMPLETE and any(
            s.state == SourceState.TRUNCATED for s in self.sources
        ):
            raise ValueError("Truncated sources cannot be marked complete")
        if self.completeness == Completeness.COMPLETE and any(
            s.state not in (SourceState.COMPLETE, SourceState.EMPTY)
            for s in self.sources
            if s.source in required_names
        ):
            raise ValueError("Required source failures cannot be marked complete")
        return self


class Event(Contract):
    schema_version: SchemaVersion = "1.0"
    event_id: Annotated[Literal[5157, 5152], BeforeValidator(actual_integer)]
    provider: Identifier
    record_id: Annotated[int, Field(ge=0, le=2**64 - 1)]
    event_version: Annotated[int, Field(ge=0, le=255)]
    timestamp_utc: UTC
    application_raw: PathText | None
    application_canonical: Program | None
    pid_raw: ShortText | None
    pid_value: Annotated[int, Field(ge=0, le=2**32 - 1)] | None
    direction: Direction
    source_address: Address | None
    source_port: Port | None
    destination_address: Address | None
    destination_port: Port | None
    protocol: Annotated[int, Field(ge=0, le=255)] | None
    filter_runtime_id: Annotated[int, Field(ge=0, le=2**64 - 1)] | None
    filter_origin: Identifier | None
    interface_index: Annotated[int, Field(ge=0, le=2**32 - 1)] | None
    source_ref: Identifier
    warnings: Annotated[tuple[ShortText, ...], Field(max_length=50)] = ()
    unknown_fields: Annotated[dict[Identifier, ShortText | None], Field(max_length=50)] = Field(
        default_factory=dict
    )

    def model_post_init(self, context: object, /) -> None:
        # The locked CPython/Pydantic JSON validator leaves an oversized field-name
        # set per event (2264 bytes for22 names). An independent set copy is1240
        # bytes on this runtime. Preserve its exact contents/type and per-instance
        # ownership; never share a mutable set or change any diagnostic field.
        object.__setattr__(self, "__pydantic_fields_set__", self.__pydantic_fields_set__.copy())

    @model_validator(mode="after")
    def consistent_address_family(self) -> Self:
        if (
            self.source_address is not None
            and self.destination_address is not None
            and ip_address(self.source_address).version
            != ip_address(self.destination_address).version
        ):
            raise ValueError("Event endpoints must use one address family")
        return self


class PolicyConditions(Contract):
    """Null means unknown, while an empty tuple means a real empty captured condition."""

    programs: Annotated[tuple[PathText, ...], Field(max_length=100)] | None
    protocols: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    local_ports: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    remote_ports: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    local_addresses: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    remote_addresses: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    services: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    interfaces: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    interface_types: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None
    security: Annotated[tuple[ShortText, ...], Field(max_length=100)] | None


class Rule(Contract):
    rule_id: RuleIdentifier
    display_name: ShortText
    enabled: bool | None
    action: Literal["Allow", "Block", "unknown"]
    direction: Direction
    profiles: Annotated[tuple[Profile, ...], Field(max_length=3)] | None
    policy_source: ShortText | None
    policy_source_type: Literal["local", "GPO", "MDM", "other", "unknown"]
    snapshot_utc: UTC
    conditions: PolicyConditions
    filter_errors: Annotated[tuple[ShortText, ...], Field(max_length=100)] = ()
    source_ref: Identifier


class FirewallProfile(Contract):
    profile: Profile
    enabled: bool | None
    active: bool | None
    default_inbound: Literal["Allow", "Block", "unknown"]
    default_outbound: Literal["Allow", "Block", "unknown"]
    allow_local_rule_merge: bool | None
    policy_source: ShortText | None = None
    policy_source_type: Literal["local", "GPO", "MDM", "other", "unknown"] = "unknown"
    source_ref: Identifier


class CollectionError(Contract):
    source: SourceName
    code: Identifier
    summary: ShortText
    occurrences: Annotated[int, Field(ge=1, le=100000)] = 1


class NetworkInterface(Contract):
    interface_index: Annotated[int, Field(ge=0, le=2**32 - 1)]
    name: ShortText | None
    addresses: Annotated[tuple[Address, ...], Field(max_length=100)]
    active_profile: Profile | None
    state: Literal["up", "down", "unknown"]
    source_ref: Identifier


class NetworkSnapshot(Contract):
    schema_version: SchemaVersion = "1.0"
    observed_at_utc: UTC
    interfaces: Annotated[tuple[NetworkInterface, ...], Field(max_length=512)]

    @model_validator(mode="after")
    def distinct_interfaces(self) -> Self:
        if len({i.interface_index for i in self.interfaces}) != len(self.interfaces):
            raise ValueError("Network interface indexes must be distinct")
        return self


class TextObservation(Contract):
    source_ref: Identifier
    timestamp_wall: datetime
    timestamp_utc: UTC | None
    time_basis: Literal["recorded_utc", "recorded_offset", "unknown"]
    action: Literal["DROP", "ALLOW"]
    protocol: Literal["TCP", "UDP", "ICMP", "ICMPV6"]
    source_address: Address | None
    destination_address: Address | None
    source_port: Port | None
    destination_port: Port | None
    fields: Annotated[
        tuple[tuple[Identifier, Annotated[str, Field(max_length=4096)] | None], ...],
        Field(max_length=64),
    ]

    @model_validator(mode="after")
    def time_and_identity_bounds(self) -> Self:
        if self.timestamp_wall.tzinfo is not None:
            raise ValueError(
                "The recorded text wall time must remain separate from timezone interpretation"
            )
        if (self.time_basis == "unknown") != (self.timestamp_utc is None):
            raise ValueError("Unknown text time cannot claim UTC conversion")
        return self


class RejectedTextRecord(Contract):
    source_ref: Identifier
    reason: Identifier


class TextLogResult(Contract):
    observations: Annotated[tuple[TextObservation, ...], Field(max_length=100000)]
    rejected: Annotated[tuple[RejectedTextRecord, ...], Field(max_length=100001)]
    truncated: bool
    application_identity_available: NonExecutable = False
    proposal_eligible: NonExecutable = False


class Intent(Contract):
    schema_version: SchemaVersion = "1.0"
    application_path: Program
    application_identity_confirmed: bool
    direction: Literal["inbound", "outbound"]
    protocol: Literal["TCP"]
    profile: Profile
    remote_addresses: Annotated[tuple[Peer, ...], Field(min_length=1, max_length=16)]
    local_port: Annotated[int, Field(ge=1, le=65535)] | None
    remote_port: Annotated[int, Field(ge=1, le=65535)] | None
    purpose: Annotated[str, Field(min_length=1, max_length=500)]

    @model_validator(mode="after")
    def service_port_matches_direction(self) -> Self:
        if self.direction == "inbound" and (
            self.local_port is None or self.remote_port is not None
        ):
            raise ValueError(
                "Inbound intent needs the local service port and no fixed remote client port"
            )
        if self.direction == "outbound" and (
            self.remote_port is None or self.local_port is not None
        ):
            raise ValueError(
                "Outbound intent needs the remote service port and no fixed local client port"
            )
        return self


class Finding(Contract):
    finding_id: Identifier
    category: Category
    evidence_grade: EvidenceGrade
    summary: ShortText
    observation: Annotated[str, Field(max_length=2000)]
    evidence_refs: Annotated[tuple[Identifier, ...], Field(max_length=100)]
    candidate_rules: Annotated[tuple[RuleIdentifier, ...], Field(max_length=100)] = ()
    policy_snapshot_utc: UTC | None
    relevance: Relevance
    limitations: Annotated[tuple[ShortText, ...], Field(max_length=100)] = ()
    alternative_explanations: Annotated[tuple[ShortText, ...], Field(max_length=100)] = ()
    next_steps: Annotated[tuple[NextStep, ...], Field(max_length=20)]
    proposal_eligible: bool
    refusal_codes: Annotated[tuple[Identifier, ...], Field(max_length=50)] = ()
    event: Event | None = None
    event_refs: Annotated[tuple[Identifier, ...], Field(max_length=90)] = ()

    @model_validator(mode="after")
    def eligibility_invariants(self) -> Self:
        if self.proposal_eligible and (
            self.category != Category.DEFAULT_BLOCK
            or self.evidence_grade == EvidenceGrade.UNKNOWN
            or self.relevance != Relevance.RELEVANT
            or self.refusal_codes
            or not self.evidence_refs
        ):
            raise ValueError("Only relevant supported default blocks can be eligible")
        return self


class Analysis(Contract):
    schema_version: SchemaVersion = "1.0"
    run_id: Identifier
    engine_version: Identifier
    analyzed_at_utc: UTC
    completeness: Completeness
    sources: Annotated[tuple[SourceStatus, ...], Field(min_length=5, max_length=7)]
    findings: Annotated[tuple[Finding, ...], Field(max_length=100002)]
    intent: Intent | None
    host: Host | None = None
    collected_at_utc: UTC | None = None
    policy_snapshot_utc: UTC | None = None
    policy_change_observed: bool | None = None
    profiles: Annotated[tuple[FirewallProfile, ...], Field(max_length=3)] | None = None
    policy_rules: Annotated[tuple[Rule, ...], Field(max_length=10000)] | None = None
    network: NetworkSnapshot | None = None
    firewall_log: TextLogResult | None = None

    @model_validator(mode="after")
    def result_invariants(self) -> Self:
        if self.completeness == Completeness.COMPLETE and (
            any(s.state == SourceState.TRUNCATED for s in self.sources)
            or (self.firewall_log is not None and self.firewall_log.truncated)
        ):
            raise ValueError("Truncation cannot produce a complete analysis")
        if self.firewall_log is not None and not any(
            s.source == "firewall-log" for s in self.sources
        ):
            raise ValueError("Text observations need a declared analysis source")
        if len({s.source for s in self.sources}) != len(self.sources):
            raise ValueError("Analysis source statuses must be distinct")
        if self.profiles is not None and len({p.profile for p in self.profiles}) != len(
            self.profiles
        ):
            raise ValueError("Analysis profiles must be distinct")
        if self.policy_rules is not None and len(
            {r.rule_id.casefold() for r in self.policy_rules}
        ) != len(self.policy_rules):
            raise ValueError("Analysis stable rule IDs must be distinct")
        ids = [f.finding_id for f in self.findings]
        if len(set(ids)) != len(ids):
            raise ValueError("Finding IDs must be distinct")
        required = {"host", "profiles", "rules", "events", "collection-errors"}
        if {s.source for s in self.sources} != required | {
            s.source for s in self.sources if s.source in ("network", "firewall-log")
        }:
            raise ValueError("Analysis must preserve required source statuses")
        if self.completeness == Completeness.COMPLETE and any(
            s.state not in (SourceState.COMPLETE, SourceState.EMPTY)
            for s in self.sources
            if s.source in required
        ):
            raise ValueError("Failed required sources cannot produce a complete analysis")
        if (self.completeness != Completeness.COMPLETE or self.intent is None) and any(
            f.proposal_eligible for f in self.findings
        ):
            raise ValueError("Incomplete or intent-free analysis cannot permit proposals")
        if (
            self.intent is not None
            and not self.intent.application_identity_confirmed
            and any(f.proposal_eligible for f in self.findings)
        ):
            raise ValueError("Unconfirmed application identity cannot permit proposals")
        return self


class Proposal(Contract):
    schema_version: SchemaVersion = "1.0"
    executable: NonExecutable = False
    action: Literal["Allow"] = "Allow"
    finding_id: Identifier
    direction: Literal["inbound", "outbound"]
    program: Program
    protocol: Literal["TCP"] = "TCP"
    service_port: Annotated[int, Field(ge=1, le=65535)]
    peer_scope: Annotated[tuple[Peer, ...], Field(min_length=1, max_length=16)]
    profile: Profile
    evidence_refs: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=100)]
    assumptions: Annotated[tuple[ShortText, ...], Field(max_length=50)]
    review_steps: Annotated[tuple[ShortText, ...], Field(min_length=1, max_length=50)]
    change_request_description: Annotated[str, Field(min_length=1, max_length=2000)]
