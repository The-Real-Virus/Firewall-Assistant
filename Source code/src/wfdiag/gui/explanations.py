"""Plain fixed language from engine states, never imported free text."""

from wfdiag.contracts.models import Analysis


def case_explanation(analysis: Analysis, synthetic: bool = False) -> str:
    if synthetic:
        return "Training example — invented records, not findings about your computer.\nSee how a blocked connection can be investigated, then review the finding and its limitations below."
    events = next((s for s in analysis.sources if s.source == "events"), None)
    if events is None:
        return "The required blocking-event source is missing. We cannot determine whether this connection was blocked. Obtain a complete collected case from an authorized operator."
    if events.state.value == "access_denied":
        return "We cannot determine whether your connection was blocked.\nWindows did not allow access to blocking-event logs. Other collected settings are still available.\nNext: request Windows permission for a read-only collection, or ask an authorized administrator for a collected case."
    if events.state.value not in ("complete", "empty"):
        return "The investigation is missing usable blocking-event evidence.\nThe log could not be read completely. Review collection details and collect again when the source is available. This does not establish whether the application was allowed or blocked."
    if not events.records:
        if any("FAILURE_DISABLED" in code for code in events.warnings):
            return "No blocking events were found. Windows system audit settings do not enable all required failure events; other audit policies may also apply.\nFirewall settings cannot prove what happened to this connection. Ask your administrator about approved recording, then reproduce the failure and collect a new case."
        return "No recorded blocking event was found in this time window.\nThis does not prove the firewall allowed the connection. Reproduce the real failure, cover that time in the collection window, and review whether Windows is recording the required events."
    if analysis.completeness.value == "incomplete":
        return "Blocking events were read, but other evidence is incomplete.\nReview the findings and missing sources together. Missing data cannot establish a specific cause or justify a change."
    return "Recorded blocking events and firewall settings are available for review.\nFindings explain observations, relevance and remaining uncertainty. A finding or proposal does not prove the problem has been repaired."


def proposal_explanation(analysis: Analysis, eligible: bool, synthetic: bool, stale: bool) -> str:
    if synthetic:
        return "This is training data. No operational change proposal is exported from invented evidence."
    if stale:
        return "Connection details changed. Analyze the original collected case again before requesting a proposal."
    if analysis.completeness.value == "incomplete":
        return "A proposal is unavailable because evidence is missing. Read the explanation above and obtain the missing evidence before considering a firewall change."
    if analysis.intent is None:
        return "General review does not define a connection to allow. Supply verified application and connection details and analyze the original case again to request a narrow proposal."
    if not eligible:
        return "The evidence does not support a safe local allow proposal. Explicit blocks, managed policy, unknown conditions or an unconfirmed connection may need the policy owner's review. Technical refusal details are below."
    return "An administrator can review the exported narrow proposal. It is a document, not an applied firewall change; the application never executes it."
