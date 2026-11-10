import json
from html.parser import HTMLParser

from engine_data import Scenario, changed

from wfdiag.contracts.models import Analysis
from wfdiag.parsers.firewall_log import parse_firewall_log
from wfdiag.reporting.render import render_report
from wfdiag.reporting.share import make_share_report

CANARY = "WF_TEST_SECRET_CANARY_6723"
DISCLOSURES = (
    CANARY,
    "employee-host-77",
    "SecretUserΩ",
    r"C:\Users\SecretUserΩ\App.exe",
    "10.23.42.17",
    "2001:db8:abcd::17",
    "https://internal.example/private",
    '<script>alert("secret")</script>',
    "color:red;url(https://untrusted.invalid)",
)


class ActiveContent(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.active: list[str] = []
        self.headings = 0
        self.source_tables = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {
            "script",
            "iframe",
            "object",
            "embed",
            "link",
            "img",
            "form",
            "audio",
            "video",
            "a",
        }:
            self.active.append(tag)
        for name, _ in attrs:
            if name.startswith("on") or name in ("src", "href", "action", "srcdoc"):
                self.active.append(name)
        self.headings += tag in {"h1", "h2", "h3"}
        self.source_tables += tag == "table"


def poisoned_analysis(scenario: Scenario):
    analysis = scenario.analyze()
    finding = analysis.findings[0]
    text = " | ".join(DISCLOSURES)
    finding = changed(
        finding,
        finding_id=CANARY,
        summary=text[:500],
        observation=text,
        evidence_refs=[CANARY, "source:" + DISCLOSURES[1]],
        candidate_rules=[CANARY],
        limitations=[text[:500]],
        alternative_explanations=[text[:500]],
        proposal_eligible=False,
        refusal_codes=[CANARY],
    )
    intent = changed(scenario.intent, purpose=text[:500], application_path=DISCLOSURES[3])
    sources = [
        changed(source, warnings=[text[:500]]).model_dump(mode="json")
        for source in analysis.sources
    ]
    sources.append(
        {
            "source": "firewall-log",
            "state": "complete",
            "window_start_utc": None,
            "window_end_utc": None,
            "records": 1,
            "warnings": [],
        }
    )
    text_log = parse_firewall_log(
        [
            b"#Fields: date time action protocol src-ip dst-ip src-port dst-port note\n",
            f"2026-11-01 00:05:00 DROP TCP 192.0.2.1 192.0.2.2 51000 443 {CANARY}\n".encode(),
        ]
    )
    return changed(
        analysis,
        findings=[finding.model_dump(mode="json")],
        intent=intent.model_dump(mode="json"),
        run_id=CANARY,
        sources=sources,
        firewall_log=text_log.model_dump(mode="json"),
    )


def test_share_json_contains_no_canary_identity_or_free_text(scenario: Scenario) -> None:
    output = render_report(poisoned_analysis(scenario), mode="share", format="json").decode()
    payload = json.loads(output)
    for value in DISCLOSURES:
        assert value not in output
    assert payload["mode"] == "share" and payload["review_required"] is True
    assert payload["findings"][0]["refusal_codes"] == ["ADDITIONAL_RESTRICTION"]
    assert payload["findings"][0]["category"] == "DEFAULT_BLOCK"
    assert payload["sources"][0]["warnings_present"] is True
    assert "intent" not in payload and "run_id" not in payload


def test_share_html_uses_same_allowlisted_derivative(scenario: Scenario) -> None:
    output = render_report(poisoned_analysis(scenario), mode="share", format="html").decode()
    for value in DISCLOSURES:
        assert value not in output
    assert "Review before sharing" in output
    assert "Pseudonyms do not guarantee anonymity" in output
    assert "DEFAULT_BLOCK" in output


def test_full_html_escapes_untrusted_text_instead_of_executing_it(scenario: Scenario) -> None:
    output = render_report(poisoned_analysis(scenario), mode="full", format="html").decode()
    parser = ActiveContent()
    parser.feed(output)
    assert not parser.active
    assert CANARY in output
    assert "&lt;script&gt;" in output
    assert '<script>alert("secret")</script>' not in output
    assert parser.headings >= 4 and parser.source_tables == 1
    assert "default-src &#39;none&#39;" in output or "default-src 'none'" in output


def test_aliases_are_consistent_within_a_report_and_random_between_reports(
    scenario: Scenario,
) -> None:
    analysis = scenario.analyze()
    one = make_share_report(analysis)
    two = make_share_report(analysis)
    assert one.report_id != two.report_id
    assert one.findings[0].finding_alias != two.findings[0].finding_alias
    assert one.findings[0].evidence_aliases != two.findings[0].evidence_aliases
    serialized = one.model_dump_json()
    assert "reverse" not in serialized and "events:1" not in serialized


def test_reports_preserve_refusal_and_completeness_without_cloud_code(scenario: Scenario) -> None:
    scenario.manifest = changed(scenario.manifest, policy_change_observed=None)
    analysis = scenario.analyze()
    output = json.loads(render_report(analysis, mode="share", format="json"))
    assert output["completeness"] == analysis.completeness.value
    assert output["findings"][0]["proposal_eligible"] is False
    assert "POLICY_CONTINUITY_UNKNOWN" in output["findings"][0]["refusal_codes"]


def test_full_json_round_trips_the_exact_analysis(scenario: Scenario) -> None:
    analysis = scenario.analyze()
    body = render_report(analysis, mode="full", format="json")
    assert Analysis.model_validate_json(body) == analysis
    assert json.loads(body)["schema_version"] == analysis.schema_version
