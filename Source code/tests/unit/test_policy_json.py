import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.unit.native_policy_data import native_rule_data
from wfdiag.contracts.enums import Direction, Profile
from wfdiag.parsers.policy_json import NativeRule, normalize_profile, normalize_rule

NOW = datetime(2026, 11, 3, tzinfo=UTC)


def test_long_native_rule_identity_is_preserved_through_related_contracts() -> None:

    from wfdiag.contracts.comparison import RuleChange
    from wfdiag.contracts.models import Analysis, Finding

    identity = "synthetic-native-policy-" + "x" * 800
    data = native_rule_data()
    data["rule"]["Name"] = [identity]
    result = normalize_rule(NativeRule.model_validate_json(json.dumps(data)), NOW, "rules:1")
    assert result.rule_id == identity
    example = Path(__file__).parents[2] / "examples/expected-analysis.json"
    payload = Analysis.model_validate_json(example.read_bytes()).findings[0].model_dump(mode="json")
    payload["candidate_rules"] = [identity]
    assert Finding.model_validate_json(json.dumps(payload)).candidate_rules == (identity,)
    change = RuleChange.model_validate_json(
        json.dumps(
            {
                "rule_id": identity,
                "change": "added",
                "changed_fields": [],
                "before": None,
                "after": result.model_dump(mode="json"),
            }
        )
    )
    assert change.after is not None
    assert change.rule_id == change.after.rule_id == identity


def test_native_rule_identity_bound_remains_enforced() -> None:
    from pydantic import ValidationError

    data = native_rule_data()
    data["rule"]["Name"] = ["x" * 4097]
    with pytest.raises(ValidationError):
        NativeRule.model_validate_json(json.dumps(data))


def test_native_rule_keeps_stable_identity_and_all_conditions() -> None:
    raw = NativeRule.model_validate_json(json.dumps(native_rule_data()))
    result = normalize_rule(raw, NOW, "rules:1")
    assert result.rule_id == "synthetic-stable-rule" and result.display_name == "Invented Ω policy"
    assert result.conditions.programs == (r"C:\Training\例 Ω.exe",)
    assert result.direction == Direction.OUTBOUND and result.profiles == (Profile.PRIVATE,)
    assert result.conditions.remote_ports == ("443",) and result.conditions.local_ports == ("Any",)
    assert result.conditions.remote_addresses == ("192.0.2.10/32",)
    assert (
        result.conditions.services
        == result.conditions.interfaces
        == result.conditions.interface_types
        == ("Any",)
    )
    assert result.conditions.security == () and not result.filter_errors
    assert result.policy_source_type == "local" and result.snapshot_utc == NOW


@pytest.mark.parametrize(
    "group",
    ["application", "port", "address", "service", "interface", "interface_type", "security"],
)
def test_missing_filter_stays_unknown(group: str) -> None:
    data = native_rule_data()
    data["filters"][group] = None
    data["filter_errors"] = ["SYNTHETIC_FILTER_DENIED"]
    result = normalize_rule(NativeRule.model_validate_json(json.dumps(data)), NOW, "rules:1")
    assert "SYNTHETIC_FILTER_DENIED" in result.filter_errors
    assert None in result.conditions.model_dump().values()


@pytest.mark.parametrize(
    "group,key,value",
    [
        ("application", "Package", ["UnresolvedPackage"]),
        ("security", "Authentication", ["Required"]),
        ("port", "DynamicTarget", ["RPC"]),
        ("interface", "UnrecognizedConstraint", None),
    ],
)
def test_unhandled_conditions_are_never_unrestricted(group: str, key: str, value: object) -> None:
    data = native_rule_data()
    data["filters"][group][key] = value
    result = normalize_rule(NativeRule.model_validate_json(json.dumps(data)), NOW, "rules:1")
    assert result.conditions.security and any(key in v for v in result.conditions.security)


def test_display_name_is_not_an_identity_fallback() -> None:
    data = native_rule_data()
    del data["rule"]["Name"]
    with pytest.raises(ValueError, match="persistent"):
        normalize_rule(NativeRule.model_validate_json(json.dumps(data)), NOW, "rules:1")


def test_unknown_enum_values_and_provenance_are_not_false_defaults() -> None:
    data = native_rule_data()
    data["rule"].update(
        Enabled=["NotConfigured"],
        Action=["999"],
        Direction=["Localized direction"],
        Profile=["Unknown profile"],
        PolicyStoreSourceType=None,
        NewCondition=None,
    )
    result = normalize_rule(NativeRule.model_validate_json(json.dumps(data)), NOW, "rules:1")
    assert result.enabled is None and result.action == "unknown"
    assert result.direction == Direction.UNKNOWN and result.profiles is None
    assert result.policy_source_type == "unknown"
    assert result.conditions.security and "NewCondition=<unknown>" in result.conditions.security[0]


def test_profile_null_is_not_disabled_and_merge_remains_unknown() -> None:
    profile = normalize_profile(
        {
            "Name": ("Private",),
            "Enabled": ("NotConfigured",),
            "DefaultInboundAction": ("Block",),
            "DefaultOutboundAction": ("Allow",),
            "AllowLocalFirewallRules": None,
        },
        None,
        "profiles:1",
    )
    assert (
        profile.enabled is None
        and profile.active is None
        and profile.allow_local_rule_merge is None
    )
    assert profile.default_inbound == "Block" and profile.policy_source_type == "unknown"


def test_many_unknown_native_conditions_remain_bounded_restrictions():
    data = native_rule_data()
    for group in ("application", "address"):
        data["filters"][group].update({f"Unrecognized{i}": ["present"] for i in range(90)})
    result = normalize_rule(NativeRule.model_validate_json(json.dumps(data)), NOW, "rules:1")
    assert len(result.conditions.security) == 100
    assert result.conditions.security[-1] == "ADDITIONAL_UNSUPPORTED_CONDITION_DETAILS_CAPPED"
    assert result.conditions.security[0].startswith("address.Unrecognized")


@pytest.mark.parametrize("security_present", [True, False])
def test_large_unknown_condition_never_becomes_unrestricted_or_rejects_entire_rule(
    security_present,
):
    data = native_rule_data()
    data["filters"]["application"]["UnrecognizedLargeConstraint"] = ["x" * 2000]
    if not security_present:
        data["filters"]["security"] = None
    result = normalize_rule(NativeRule.model_validate_json(json.dumps(data)), NOW, "rules:1")
    if security_present:
        assert any("sha256:" in v for v in result.conditions.security)
    else:
        assert result.conditions.security is None
        assert any("sha256" in v.casefold() for v in result.filter_errors)
    assert all(len(v) <= 128 for v in result.filter_errors)
