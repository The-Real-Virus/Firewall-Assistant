from engine_data import Scenario, changed, rule

from wfdiag.analysis.compare import compare_analyses


def test_no_later_relevant_event_never_proves_repair(scenario: Scenario) -> None:
    before = scenario.analyze()
    after = scenario.analyze(events=())
    result = compare_analyses(before, after)
    assert result.observation_change == "not_observed"
    assert result.repair_status == "not_established"
    assert "does not prove repair" in result.conclusion
    assert result.before_sources != result.after_sources


def test_actual_policy_changes_preserve_before_and_after_values(scenario: Scenario) -> None:
    scenario.rules = (rule(scenario),)
    before = scenario.analyze()
    scenario.rules = (changed(scenario.rules[0], enabled=False),)
    scenario.profiles = tuple(changed(p, allow_local_rule_merge=False) for p in scenario.profiles)
    result = compare_analyses(before, scenario.analyze())
    (delta,) = result.rule_changes
    assert delta.changed_fields == ("enabled",)
    assert delta.before.enabled is True and delta.after.enabled is False
    assert len(result.profile_changes) == 3
    assert result.policy_comparison == "available"


def test_rule_snapshot_time_alone_is_not_a_policy_change(scenario: Scenario) -> None:
    scenario.rules = (rule(scenario),)
    before = scenario.analyze()
    scenario.rules = (changed(scenario.rules[0], snapshot_utc="2026-11-01T00:05:40Z"),)
    result = compare_analyses(before, scenario.analyze())
    assert result.rule_changes == ()


def test_missing_policy_context_stays_unavailable(scenario: Scenario) -> None:
    before = changed(scenario.analyze(), policy_rules=None)
    result = compare_analyses(before, scenario.analyze())
    assert result.policy_comparison == "unavailable"
    assert "POLICY_CONTEXT_UNAVAILABLE" in result.warnings
    assert not result.rule_changes


def test_different_intents_make_observation_comparison_uncertain(scenario: Scenario) -> None:
    before = scenario.analyze()
    scenario.intent = changed(scenario.intent, local_port=8888)
    result = compare_analyses(before, scenario.analyze())
    assert result.observation_change == "unknown" and "INTENTS_DIFFER" in result.warnings


def test_same_inputs_produce_stable_comparison(scenario: Scenario) -> None:
    before = scenario.analyze()
    one = compare_analyses(before, before)
    assert one.observation_change == "unchanged"
    assert one == compare_analyses(before, before)
