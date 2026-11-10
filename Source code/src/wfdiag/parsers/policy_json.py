"""Normalize fixed NetSecurity records without turning missing conditions into Any."""

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from wfdiag.contracts.base import Contract, Identifier
from wfdiag.contracts.enums import Direction, Profile
from wfdiag.contracts.models import FirewallProfile, Rule

NativeText = Annotated[str, Field(max_length=4096)]
NativeValues = Annotated[tuple[NativeText, ...], Field(max_length=100)]
NativeFields = Annotated[dict[Identifier, NativeValues | None], Field(max_length=100)]
FilterName = Literal[
    "application", "address", "port", "service", "interface", "interface_type", "security"
]


class NativeRule(Contract):
    rule: NativeFields
    filters: Annotated[dict[FilterName, NativeFields | None], Field(min_length=7, max_length=7)]
    filter_errors: Annotated[
        tuple[Annotated[str, Field(max_length=128)], ...], Field(max_length=100)
    ]


METADATA = frozenset(
    {
        "Caption",
        "Description",
        "ElementName",
        "InstanceID",
        "Name",
        "PolicyStoreSource",
        "PolicyStoreSourceType",
        "Status",
        "CommunicationStatus",
        "DetailedStatus",
        "HealthState",
        "InstallDate",
        "OperatingStatus",
        "OperationalStatus",
        "PrimaryStatus",
        "StatusDescriptions",
        "SystemCreationClassName",
        "SystemName",
        "CreationClassName",
    }
)
RULE_FIELDS = METADATA | {
    "CommonName",
    "ConditionListType",
    "ExecutionStrategy",
    "Mandatory",
    "PolicyKeywords",
    "PolicyRoles",
    "PolicyRuleName",
    "Priority",
    "RuleUsage",
    "SequencedActions",
    "DisplayName",
    "Enabled",
    "Direction",
    "Action",
    "Profile",
    "DisplayGroup",
    "Group",
    "PrimaryStatus",
    "EnforcementStatus",
    "StatusCode",
    "CreationClassName",
    "PolicyDecisionStrategy",
}
FILTER_FIELDS = {
    "application": {"Program", "Package", "PolicyAppId"},
    "address": {"LocalAddress", "RemoteAddress"},
    "port": {"Protocol", "LocalPort", "RemotePort", "IcmpType", "DynamicTarget"},
    "service": {"Service"},
    "interface": {"InterfaceAlias"},
    "interface_type": {"InterfaceType"},
    "security": {
        "Authentication",
        "Encryption",
        "OverrideBlockRules",
        "LocalUser",
        "RemoteUser",
        "RemoteMachine",
    },
}


def one(fields: NativeFields, key: str) -> str | None:
    values = fields.get(key)
    return values[0] if values is not None and len(values) == 1 else None


def boolean(value: str | None) -> bool | None:
    return {"true": True, "false": False}.get(value.casefold()) if value is not None else None


def action(value: str | None) -> Literal["Allow", "Block", "unknown"]:
    return "Allow" if value == "Allow" else "Block" if value == "Block" else "unknown"


def ownership(value: str | None) -> Literal["local", "GPO", "MDM", "other", "unknown"]:
    if value == "Local":
        return "local"
    if value == "GroupPolicy":
        return "GPO"
    if value == "MDM":
        return "MDM"
    return "other" if value in ("Dynamic", "Generated", "Hardcoded") else "unknown"


def rule_profiles(values: NativeValues | None) -> tuple[Profile, ...] | None:
    if not values:
        return None
    if values == ("Any",):
        return tuple(Profile)
    try:
        profiles = tuple(Profile(part.strip()) for value in values for part in value.split(","))
    except ValueError:
        return None
    return profiles if len(profiles) == len(set(profiles)) and len(profiles) <= 3 else None


def normalize_rule(raw: NativeRule, snapshot: datetime, source_ref: str) -> Rule:
    native = raw.rule
    identifier = one(native, "Name") or one(native, "InstanceID")
    if not identifier:
        raise ValueError("No persistent rule identifier")
    unsupported: list[str] = []
    capped = False

    def marker(group: str, key: str, values: NativeValues | None) -> None:
        nonlocal capped
        text = f"{group}.{key}=" + (
            "<unknown>" if values is None else json.dumps(values, ensure_ascii=False)
        )
        if len(text) > 500:
            text = (
                f"{group}.{key}=<detail capped; sha256:{hashlib.sha256(text.encode()).hexdigest()}>"
            )
            capped = True
        if len(unsupported) < 99:
            unsupported.append(text)
        else:
            capped = True

    for key in sorted(native.keys() - RULE_FIELDS):
        values = native[key]
        neutral = {
            "EdgeTraversalPolicy": ("Block",),
            "LooseSourceMapping": ("False",),
            "LocalOnlyMapping": ("False",),
            "Owner": ("",),
        }.get(key)
        if neutral is None or values != neutral:
            marker("rule", key, values)
    for group, fields in sorted(raw.filters.items()):
        if fields is not None:
            for key in sorted(fields.keys() - (METADATA | FILTER_FIELDS[group])):
                if key == "IsNegated" and fields[key] == ("False",):
                    continue
                marker(group, key, fields[key])

    application = raw.filters["application"]
    port = raw.filters["port"]
    security = raw.filters["security"]
    for key in ("Package",):
        values = application.get(key) if application is not None else None
        if values not in (("Any",), ("",), ()):
            marker("application", key, values)
    if application is not None and "PolicyAppId" in application:
        values = application["PolicyAppId"]
        if values not in (("Any",), ("",), ()):
            marker("application", "PolicyAppId", values)
    if port is not None:
        for key in ("IcmpType", "DynamicTarget"):
            if key in port and port[key] not in (("Any",), ("",), ()):
                marker("port", key, port[key])
    if security is not None:
        for key, neutral in {
            "Authentication": ("NotRequired",),
            "Encryption": ("NotRequired",),
            "OverrideBlockRules": ("False",),
            "LocalUser": ("Any",),
            "RemoteUser": ("Any",),
            "RemoteMachine": ("Any",),
        }.items():
            if security.get(key) != neutral:
                marker("security", key, security.get(key))

    def condition_values(group: FilterName, key: str) -> NativeValues | None:
        fields = raw.filters[group]
        return fields.get(key) if fields is not None else None

    direction = one(native, "Direction")
    if capped:
        unsupported.append("ADDITIONAL_UNSUPPORTED_CONDITION_DETAILS_CAPPED")
    filter_errors = list(raw.filter_errors) + (unsupported if security is None else [])
    if len(filter_errors) > 100:
        filter_errors = filter_errors[:99] + ["ADDITIONAL_UNSUPPORTED_CONDITION_DETAILS_CAPPED"]
    filter_errors = [
        value
        if len(value) <= 128
        else "UNSUPPORTED_CONDITION_SHA256_" + hashlib.sha256(value.encode()).hexdigest()
        for value in filter_errors
    ]
    return Rule.model_validate_json(
        json.dumps(
            {
                "rule_id": identifier,
                "display_name": one(native, "DisplayName") or identifier,
                "enabled": boolean(one(native, "Enabled")),
                "action": action(one(native, "Action")),
                "direction": direction.casefold()
                if direction in ("Inbound", "Outbound")
                else Direction.UNKNOWN.value,
                "profiles": rule_profiles(native.get("Profile")),
                "policy_source": one(native, "PolicyStoreSource"),
                "policy_source_type": ownership(one(native, "PolicyStoreSourceType")),
                "snapshot_utc": snapshot.isoformat(),
                "conditions": {
                    "programs": condition_values("application", "Program"),
                    "protocols": condition_values("port", "Protocol"),
                    "local_ports": condition_values("port", "LocalPort"),
                    "remote_ports": condition_values("port", "RemotePort"),
                    "local_addresses": condition_values("address", "LocalAddress"),
                    "remote_addresses": condition_values("address", "RemoteAddress"),
                    "services": condition_values("service", "Service"),
                    "interfaces": condition_values("interface", "InterfaceAlias"),
                    "interface_types": condition_values("interface_type", "InterfaceType"),
                    "security": unsupported if security is not None else None,
                },
                "filter_errors": filter_errors,
                "source_ref": source_ref,
            }
        )
    )


def normalize_profile(
    fields: NativeFields, active: bool | None, source_ref: str
) -> FirewallProfile:
    return FirewallProfile.model_validate_json(
        json.dumps(
            {
                "profile": one(fields, "Name"),
                "enabled": boolean(one(fields, "Enabled")),
                "active": active,
                "default_inbound": action(one(fields, "DefaultInboundAction")),
                "default_outbound": action(one(fields, "DefaultOutboundAction")),
                "allow_local_rule_merge": boolean(one(fields, "AllowLocalFirewallRules")),
                "policy_source": one(fields, "PolicyStoreSource"),
                "policy_source_type": ownership(one(fields, "PolicyStoreSourceType")),
                "source_ref": source_ref,
            }
        )
    )
