import pytest
from engine_data import Scenario, changed, rule

from wfdiag.contracts.models import Intent
from wfdiag.proposals.generate import ProposalRefused, generate_proposal


def test_inbound_proposal_has_exact_operator_scope_and_no_executable_payload(
    scenario: Scenario,
) -> None:
    analysis = scenario.analyze()
    proposal = generate_proposal(analysis, analysis.findings[0].finding_id, scenario.intent)
    assert proposal.executable is False
    assert proposal.direction == "inbound" and proposal.service_port == 8765
    assert proposal.peer_scope == ("192.168.56.20/32",)
    assert proposal.program == r"C:\Training\ExampleApp.exe"
    assert proposal.profile.value == "Private"
    assert proposal.evidence_refs
    assert "script" not in type(proposal).model_fields
    assert "command" not in type(proposal).model_fields


def test_outbound_proposal_never_pins_the_observed_client_port(scenario: Scenario) -> None:
    scenario.intent = changed(
        scenario.intent, direction="outbound", local_port=None, remote_port=443
    )
    scenario.event = changed(
        scenario.event,
        direction="outbound",
        source_address="192.168.56.10",
        source_port=51999,
        destination_address="192.168.56.20",
        destination_port=443,
    )
    analysis = scenario.analyze()
    proposal = generate_proposal(analysis, analysis.findings[0].finding_id, scenario.intent)
    assert proposal.service_port == 443 and proposal.direction == "outbound"
    assert "51999" not in proposal.model_dump_json()


def test_changed_intent_cannot_reuse_a_previous_eligibility_decision(scenario: Scenario) -> None:
    analysis = scenario.analyze()
    widened = changed(scenario.intent, remote_addresses=["192.168.56.0/24"])
    with pytest.raises(ProposalRefused) as caught:
        generate_proposal(analysis, analysis.findings[0].finding_id, widened)
    assert "INTENT_DIFFERS_FROM_ANALYZED_FLOW" in caught.value.refusal_codes


@pytest.mark.parametrize(
    "failure",
    ["block", "stale", "unknown_identity", "managed", "truncated", "packet", "unknown_path"],
)
def test_unsupported_case_never_generates_a_review_allow(scenario: Scenario, failure: str) -> None:
    if failure == "block":
        scenario.rules = (rule(scenario),)
    elif failure == "stale":
        scenario.manifest = changed(scenario.manifest, policy_snapshot_utc=None)
    elif failure == "unknown_identity":
        scenario.intent = changed(scenario.intent, application_identity_confirmed=False)
    elif failure == "managed":
        scenario.profiles = tuple(changed(p, policy_source_type="GPO") for p in scenario.profiles)
    elif failure == "truncated":
        sources = [s.model_dump(mode="json") for s in scenario.manifest.sources]
        sources[3]["state"] = "truncated"
        scenario.manifest = changed(scenario.manifest, completeness="incomplete", sources=sources)
    elif failure == "packet":
        scenario.event = changed(scenario.event, event_id=5152)
    elif failure == "unknown_path":
        scenario.event = changed(scenario.event, application_canonical=None)
    analysis = scenario.analyze()
    with pytest.raises(ProposalRefused):
        generate_proposal(analysis, analysis.findings[0].finding_id, scenario.intent)


def test_unknown_finding_is_not_guessed(scenario: Scenario) -> None:
    with pytest.raises(ProposalRefused) as caught:
        generate_proposal(scenario.analyze(), "not-an-existing-ID", scenario.intent)
    assert caught.value.refusal_codes == ("FINDING_NOT_FOUND",)


def test_command_looking_business_text_remains_json_data(scenario: Scenario) -> None:
    scenario.intent = changed(
        scenario.intent, purpose="Synthetic text: $(Remove-Item); <script>alert(1)</script>"
    )
    assert isinstance(scenario.intent, Intent)
    analysis = scenario.analyze()
    proposal = generate_proposal(analysis, analysis.findings[0].finding_id, scenario.intent)
    assert "$(Remove-Item)" in proposal.change_request_description
    assert proposal.executable is False


def test_imported_eligibility_flag_cannot_override_uncertain_event_facts(
    scenario: Scenario,
) -> None:
    analysis = scenario.analyze()
    finding = analysis.findings[0]
    assert finding.event is not None
    event = changed(finding.event, application_canonical=None)
    finding = changed(finding, event=event.model_dump(mode="json"))
    forged = changed(analysis, findings=[finding.model_dump(mode="json")])
    with pytest.raises(ProposalRefused) as caught:
        generate_proposal(forged, finding.finding_id, scenario.intent)
    assert "ELIGIBILITY_RECHECK_FAILED" in caught.value.refusal_codes
    assert "UNRESOLVED_APPLICATION_PATH" in caught.value.refusal_codes


def test_older_analysis_without_decision_facts_cannot_enable_proposals(scenario: Scenario) -> None:
    analysis = changed(scenario.analyze(), profiles=None, policy_rules=None)
    with pytest.raises(ProposalRefused) as caught:
        generate_proposal(analysis, analysis.findings[0].finding_id, scenario.intent)
    assert "DECISION_EVIDENCE_UNAVAILABLE" in caught.value.refusal_codes


def test_untrusted_refusal_text_is_not_echoed_to_public_error(scenario: Scenario) -> None:
    analysis = scenario.analyze()
    finding = changed(
        analysis.findings[0], proposal_eligible=False, refusal_codes=["PRIVATE_CANARY_DO_NOT_ECHO"]
    )
    analysis = changed(analysis, findings=[finding.model_dump(mode="json")])
    with pytest.raises(ProposalRefused) as caught:
        generate_proposal(analysis, finding.finding_id, scenario.intent)
    assert "PRIVATE_CANARY_DO_NOT_ECHO" in caught.value.refusal_codes
    assert "PRIVATE_CANARY_DO_NOT_ECHO" not in caught.value.public_message
