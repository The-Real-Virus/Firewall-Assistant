from pathlib import Path

from wfdiag.analysis.engine import analyze_case
from wfdiag.contracts.models import Analysis, Intent
from wfdiag.proposals.generate import generate_proposal
from wfdiag.reporting.render import render_report
from wfdiag.storage.bundle import VerifiedBundle


def test_committed_synthetic_case_reproduces_expected_engine_facts() -> None:
    root = Path(__file__).parents[2] / "examples"
    expected = Analysis.model_validate_json((root / "expected-analysis.json").read_bytes())
    intent = Intent.model_validate_json((root / "intent-synthetic-confirmed.json").read_bytes())
    with VerifiedBundle(root / "synthetic-case") as bundle:
        actual = analyze_case(
            bundle.manifest,
            bundle.profiles,
            bundle.rules,
            bundle.iter_events(),
            intent=intent,
            network=bundle.network,
            analyzed_at_utc=expected.analyzed_at_utc,
        )
        bundle.check_unchanged()
    assert actual == expected
    (finding,) = actual.findings
    assert finding.proposal_eligible
    proposal = generate_proposal(actual, finding.finding_id, intent)
    assert proposal.service_port == 8765 and proposal.executable is False
    assert b"DEFAULT_BLOCK" in render_report(actual, mode="share", format="html")
