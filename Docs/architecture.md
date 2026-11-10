# Integrated architecture

Partially implemented. One deterministic diagnostic engine owns interpretation and proposals.
Pure matching, seven-category analysis, eligibility rechecks and static reporting now exist.
Doctor/collect/analyze/report/propose/compare use shared operation services and the GUI worker.
Native collector source is integrated and fixture tested; actual native acceptance remains blocked.

CLI -> validated application services -> collectors / parsers / storage / analysis / proposals / reports.
GUI -> QProcess -> sibling wfdiag.exe desktop-job -> the same services. A source checkout uses
the approved venv console Python with -m wfdiag. Engine paths are absolute, version-checked and
resolved from the verified installation root, never PATH, the case or the current directory.

Only collectors invoke fixed trusted Windows PowerShell 5.1 resources. They never mutate
policy, elevate, launch a target, enable auditing or probe a peer. Parsers and pure analysis
do not read fresh host state. Proposal JSON is non-executable review data. Storage bounds
opened inputs and protects new atomic outputs with native Windows ACLs. Reports escape
untrusted content, contain no scripts/remote assets and reuse one tested redaction service.

The GUI owns navigation, intent editing, private preferences and plain-text views. Application
services own doctor, collect, analyze, report, propose and compare plus cancellation. Qt imports
cannot be needed for the core or ordinary CLI. A versioned bounded worker protocol, monotonic
sequence, job IDs, process outcome and output validation all agree before completion is shown.

AI is a lazy independent package and asynchronous HTTPX service. It consumes only a reviewed
allowlisted context and returns a locally validated explanation. It cannot access collectors,
firewall settings, arbitrary files, tools, intent mutation or deterministic finding writes. The
GUI keeps AI prose separate. Disabled AI creates no client or worker and causes no outbound AI
traffic. Missing dependencies, keys, settings, DNS or provider access affect only the assistant.

Trust boundaries: imported files -> validators; GUI -> local worker; worker -> fixed collector;
case records -> report/share/AI disclosure policy; masked key -> provider-scoped credential API;
consented synthetic or permitted context -> fixed HTTPS provider. Imported content cannot grant
authority at any boundary. Lab helpers remain separate from shipping resources.

Analysis retains host/profile/rule/network context, policy time/change uncertainty and normalized
event facts/references. Proposals replay the same eligibility function and require exactly the
analyzed intent; an imported eligible flag is insufficient. The entire intended peer scope is
checked for overlapping blocks. Replay and hashes do not authenticate fabricated source evidence.
Outputs are review data and never authorize execution. A current snapshot does not prove history.

Share reports construct an allowlisted derivative with fresh aliases and known engine codes.
Raw free text, intent, identities, paths, addresses, precise times and reverse maps are omitted.
Full HTML escapes all interpolation, including event/intent JSON. AI adapters and the optional
UI now have synthetic source coverage; real native credentials/live APIs remain blocked.

UI preferences have a separate strict bounded schema and fixed app-owned file. Startup obtains
a per-user private-location instance lock before reading preferences, with safe defaults for
unreadable/corrupt data. Deliberate changes save asynchronously; close waits for pending saves.
History stores only explicit operator-named entries, max20, and never substitutes for evidence
validation. Moving work location leaves prior data in place. No key or AI enabled state is stored.
Actual Windows ACL/instance acceptance is blocked; tests use explicit boundary doubles.

Findings materialize only a loaded500-row page with lazy display strings. Evidence projects at
most500 Security observations from that page. Search is debounced200ms and explicitly page-only;
hidden fields are excluded from search/sort. Revealed address/port/UTC-time sorting uses typed keys.
All model/widget updates stay on the UI thread; full input reading and validation stay on workers.

Large GUI result files use a fully validated held-file byte-offset index, retaining only
metadata and bounded view pages. A separate total count prevents a current page being
mistaken for the complete analysis. Background page reads preserve the old page until
replacement. Report/proposal/comparison services read the original full result, and AI
disclosure review traverses all pages rather than losing off-page private identities.
Small results retain the existing full Analysis path. See ADR0018 for validation,
handle lifetime, cancellation, identity checks and measured limitations.

The AI destination initially imports neither its service nor HTTPX. Explicit enable constructs
only local configuration; Review/credential actions use an owned background thread. Send starts
the optional HTTPX request on that thread's asyncio loop. Cancellation is scheduled thread-safely;
queued typed results carry a generation guard, and close waits for the owned thread to finish.
Plain-text answers and fixed local reference/step renderers cannot write engine state. Attempt
allowance survives disable/re-enable. No remembered credential is loaded automatically.

Fixed PowerShell resources stream a separate private version1 protocol. Python validates source
order, times, counts and bounds, normalizes records, and writes new private atomic case sources.
The authoring reader shares import validation while retaining a fixed incomplete marker until
commit; ordinary imports always reject that marker. No native token mapping or policy continuity
is guessed. See collectors.md for the implementation and remaining evidence dependencies.
