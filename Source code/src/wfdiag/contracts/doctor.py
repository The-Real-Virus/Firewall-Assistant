"""Preflight is an operation report, never a security-health finding."""

from typing import Annotated, Literal

from pydantic import Field

from wfdiag.contracts.base import Contract, Identifier, NonExecutable, ShortText
from wfdiag.contracts.models import UTC, Host

CapabilityState = Literal["supported", "unavailable", "denied", "unknown"]


class Capability(Contract):
    name: Literal[
        "powershell_51", "netsecurity", "security_events", "audit_visibility", "private_output"
    ]
    state: CapabilityState
    explanation: ShortText


class ProbePayload(Contract):
    schema_version: Literal["1.0"]
    administrator_token: bool
    powershell_version: Annotated[str, Field(min_length=1, max_length=100)]
    netsecurity: CapabilityState
    security_events: CapabilityState
    audit_visibility: CapabilityState
    audit_raw: Annotated[str, Field(max_length=4096)] | None


class DoctorReport(Contract):
    schema_version: Literal["1.0"] = "1.0"
    engine_version: Identifier
    checked_at_utc: UTC
    host: Host
    eligible_target: bool
    release_certified: bool
    support_note: ShortText
    administrator_token: bool | None
    capabilities: Annotated[tuple[Capability, ...], Field(min_length=5, max_length=5)]
    audit_raw: Annotated[str, Field(max_length=4096)] | None
    security_events_collected: NonExecutable = False
    firewall_policy_collected: NonExecutable = False
