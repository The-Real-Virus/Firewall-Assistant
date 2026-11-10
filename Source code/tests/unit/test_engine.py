"""Synthetic deterministic-engine scenarios, not native acceptance."""

import pytest
from engine_data import Scenario, changed, condition_rule, rule

from wfdiag.analysis.matching import Match, match_rule, relevance, scope_overlap
from wfdiag.contracts.enums import Category, Completeness, Profile, Relevance


def test_supported_default_is_eligible_only_with_all_synthetic_ground_truth(
    scenario: Scenario,
) -> None:
    result = scenario.analyze()
    (finding,) = result.findings
    assert finding.category == Category.DEFAULT_BLOCK
    assert finding.evidence_grade.value == "supported"
    assert finding.relevance == Relevance.RELEVANT
    assert finding.proposal_eligible and not finding.refusal_codes
    assert "profiles:Private" in finding.evidence_refs
    assert result == scenario.analyze()


def test_explicit_block_precedes_an_allow_and_preserves_all_candidates(scenario: Scenario) -> None:
    scenario.rules = (
        rule(scenario),
        rule(scenario, rule_id="R-allow", action="Allow", source_ref="rules:R-allow"),
    )
    finding = scenario.analyze().findings[0]
    assert finding.category == Category.EXPLICIT_BLOCK
    assert set(finding.candidate_rules) == {"R-block", "R-allow"}
    assert not finding.proposal_eligible
    assert any("does not override" in text for text in finding.limitations)


def test_direct_origin_uses_stable_rule_id_and_not_runtime_id_or_display_name(
    scenario: Scenario,
) -> None:
    scenario.rules = (rule(scenario, display_name="5157"),)
    scenario.event = changed(scenario.event, filter_origin="R-BLOCK", filter_runtime_id=5157)
    direct = scenario.analyze().findings[0]
    assert direct.category == Category.EXPLICIT_BLOCK and direct.evidence_grade.value == "confirmed"
    scenario.event = changed(scenario.event, filter_origin="5157")
    unresolved = scenario.analyze().findings[0]
    assert unresolved.category == Category.UNRESOLVED_WFP_BLOCK
    assert "UNRESOLVED_FILTER_ORIGIN" in unresolved.refusal_codes


def test_disabled_block_is_not_a_candidate(scenario: Scenario) -> None:
    scenario.rules = (rule(scenario, enabled=False),)
    finding = scenario.analyze().findings[0]
    assert finding.category == Category.DEFAULT_BLOCK
    assert finding.proposal_eligible


def test_unknown_capture_platform_cannot_permit_a_local_rule_proposal(scenario: Scenario) -> None:
    recorded_host = changed(scenario.manifest.host, windows_product_type=None)
    scenario.manifest = changed(scenario.manifest, host=recorded_host.model_dump(mode="json"))
    finding = scenario.analyze().findings[0]
    assert not finding.proposal_eligible
    assert "UNSUPPORTED_OR_UNKNOWN_CAPTURE_PLATFORM" in finding.refusal_codes


def test_profile_mismatch_and_disabled_merge_have_distinct_explanations(scenario: Scenario) -> None:
    scenario.rules = (rule(scenario, action="Allow", profiles=["Public"]),)
    assert scenario.analyze().findings[0].category == Category.PROFILE_MISMATCH
    scenario.profiles = tuple(
        changed(p, allow_local_rule_merge=False) if p.profile == Profile.PRIVATE else p
        for p in scenario.profiles
    )
    finding = scenario.analyze().findings[0]
    assert finding.category == Category.LOCAL_RULE_MERGE_RESTRICTED
    assert not finding.proposal_eligible


@pytest.mark.parametrize(
    "name,value",
    [
        ("services", ["SomeService"]),
        ("interfaces", ["Ethernet"]),
        ("interface_types", ["Wireless"]),
        ("security", ["RequireAuthentication"]),
        ("programs", None),
        ("local_ports", ["RPC"]),
        ("remote_addresses", ["LocalSubnet"]),
    ],
)
def test_unimplemented_or_unavailable_conditions_are_unknown(
    scenario: Scenario, name: str, value: object
) -> None:
    candidate = condition_rule(scenario, **{name: value})
    assert match_rule(scenario.event, candidate, Profile.PRIVATE).result == Match.UNKNOWN
    scenario.rules = (candidate,)
    finding = scenario.analyze().findings[0]
    assert finding.category == Category.UNRESOLVED_WFP_BLOCK
    assert not finding.proposal_eligible
    assert "UNHANDLED_POLICY_CONDITION" in finding.refusal_codes


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"policy_change_observed": None}, "POLICY_CONTINUITY_UNKNOWN"),
        ({"policy_change_observed": True}, "POLICY_CHANGED"),
        ({"policy_snapshot_utc": "2026-11-01T00:10:00Z"}, "STALE_OR_UNKNOWN_POLICY_SNAPSHOT"),
        ({"policy_snapshot_utc": None}, "STALE_OR_UNKNOWN_POLICY_SNAPSHOT"),
    ],
)
def test_stale_changed_or_unknown_policy_withholds_proposal(
    scenario: Scenario, changes: dict[str, object], code: str
) -> None:
    scenario.manifest = changed(scenario.manifest, **changes)
    finding = scenario.analyze().findings[0]
    assert not finding.proposal_eligible
    assert code in finding.refusal_codes


def test_managed_profile_and_matching_managed_rule_withhold_local_proposals(
    scenario: Scenario,
) -> None:
    scenario.profiles = tuple(changed(p, policy_source_type="GPO") for p in scenario.profiles)
    assert (
        "PROFILE_POLICY_OWNER_UNVERIFIED_OR_MANAGED" in scenario.analyze().findings[0].refusal_codes
    )
    scenario.rules = (rule(scenario, policy_source_type="MDM"),)
    assert "EXTERNAL_OR_UNKNOWN_POLICY_OWNER" in scenario.analyze().findings[0].refusal_codes


def test_missing_auditing_is_gap_not_a_healthy_empty_case(scenario: Scenario) -> None:
    sources = [s.model_dump(mode="json") for s in scenario.manifest.sources]
    sources[3].update(state="unavailable", records=0)
    scenario.manifest = changed(scenario.manifest, completeness="incomplete", sources=sources)
    result = scenario.analyze(events=())
    assert result.completeness == Completeness.INCOMPLETE
    assert {f.category for f in result.findings} == {Category.EVIDENCE_GAP}
    assert all(not f.proposal_eligible for f in result.findings)
    assert any("cannot establish" in f.observation for f in result.findings)


def test_empty_complete_event_source_is_not_proof_of_repair(scenario: Scenario) -> None:
    result = scenario.analyze(events=())
    assert result.completeness == Completeness.COMPLETE
    assert result.findings[0].category == Category.NO_RELEVANT_EVENT
    assert not result.findings[0].proposal_eligible


def test_unknown_application_and_pid_never_become_relevant_identity(scenario: Scenario) -> None:
    scenario.event = changed(scenario.event, application_canonical=None, pid_value=1234)
    assert relevance(scenario.event, scenario.intent) == Relevance.UNKNOWN
    assert not scenario.analyze().findings[0].proposal_eligible


def test_localized_display_name_does_not_change_matching(scenario: Scenario) -> None:
    original = rule(scenario)
    translated = changed(original, display_name="阻止 <script> تطبيق Ω")
    assert (
        match_rule(scenario.event, original, Profile.PRIVATE).result
        == match_rule(scenario.event, translated, Profile.PRIVATE).result
        == Match.YES
    )


def test_ipv6_outbound_ignores_ephemeral_local_port_for_intent(scenario: Scenario) -> None:
    scenario.intent = changed(
        scenario.intent,
        direction="outbound",
        local_port=None,
        remote_port=443,
        remote_addresses=["2001:db8::20/128"],
    )
    scenario.event = changed(
        scenario.event,
        direction="outbound",
        source_address="2001:db8::10",
        source_port=51000,
        destination_address="2001:db8::20",
        destination_port=443,
    )
    assert scenario.network is not None
    interfaces = [i.model_dump(mode="json") for i in scenario.network.interfaces]
    interfaces[0]["addresses"] = ["2001:db8::10"]
    scenario.network = changed(scenario.network, interfaces=interfaces)
    assert scenario.analyze().findings[0].proposal_eligible
    scenario.event = changed(scenario.event, source_port=52000)
    assert scenario.analyze().findings[0].proposal_eligible


def test_wider_approved_peer_scope_cannot_hide_a_block_on_another_peer(scenario: Scenario) -> None:
    scenario.intent = changed(scenario.intent, remote_addresses=["192.168.56.0/24"])
    block = condition_rule(scenario, remote_addresses=["192.168.56.30/32"])
    assert match_rule(scenario.event, block, Profile.PRIVATE).result == Match.NO
    assert scope_overlap(scenario.intent, block) == Match.YES
    scenario.rules = (block,)
    finding = scenario.analyze().findings[0]
    assert finding.category == Category.DEFAULT_BLOCK
    assert not finding.proposal_eligible
    assert "CONFLICTING_BLOCK_IN_INTENDED_SCOPE" in finding.refusal_codes


def test_duplicate_event_references_preserved_and_distinct_attempts_not_collapsed(
    scenario: Scenario,
) -> None:
    duplicate = changed(scenario.event, source_ref="events:duplicate")
    next_attempt = changed(scenario.event, record_id=2, source_ref="events:2")
    result = scenario.analyze(events=(scenario.event, duplicate, next_attempt))
    assert len(result.findings) == 2
    assert {"events:1", "events:duplicate"}.issubset(result.findings[0].evidence_refs)
    assert result.findings[0].finding_id != result.findings[1].finding_id


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"interface_index": None}, "INTERFACE_CONTEXT_UNVERIFIED"),
        ({"event_id": 5152}, "PACKET_EVENT_ONLY"),
        ({"application_canonical": r"C:\Windows\System32\svchost.exe"}, "SHARED_APPLICATION_HOST"),
        ({"event_version": 99}, "UNVERIFIED_EVENT_SCHEMA"),
        ({"unknown_fields": {"PackageSid": "unverified"}}, "UNHANDLED_EVENT_CONTEXT"),
    ],
)
def test_uncertain_or_unsupported_context_has_explicit_refusal(
    scenario: Scenario, changes: dict[str, object], code: str
) -> None:
    scenario.event = changed(scenario.event, **changes)
    finding = scenario.analyze().findings[0]
    assert not finding.proposal_eligible and code in finding.refusal_codes
