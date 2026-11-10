# Firewall Assistant User Guide

V1.0 · Handbook revision 9 November 2026 · Made By ViRuS

Firewall Assistant helps investigate Windows desktop applications that cannot connect. It brings available firewall policy, recorded blocking events and the intended connection into one investigation. Keep Windows Firewall enabled while you investigate. The application produces findings, reports and review proposals; it does not apply a firewall repair.

This guide covers the desktop application, administrator CLI and optional cloud assistant. The complete diagnostic engine works without AI, an API key or internet. This edition accompanies a release candidate for owner human review. Consult the supplied build record for the exact tested package and remaining limitations.

## 1 Start here

Extract the entire portable ZIP into a new local folder and open FirewallAssistant.exe. Use Investigate a connection when an application really fails to reach a website, server or service. Try that failing connection first, then choose Start investigation in Diagnose. The guided flow checks access, collects recent evidence and explains the result. Leave AI off unless you want cloud assistance.

Open example is a separate training exercise with invented evidence. Its findings are not about your computer. Explore Findings, Evidence, Proposal and Export there before investigating a real failure; policy details appear within Evidence.

The navigation rail contains Overview, Diagnose, Cases, Compare, Settings and AI Assistant. The footer shows the version, AI status, Made By ViRuS and the author's GitHub and LinkedIn links. Those links open your browser only when clicked.

## 2 Requirements and supported scope

| Item | Requirement or behavior |
|---|---|
| Windows target | Standard x64 desktop editions of Windows 10 1809 or newer and Windows 11, including Home, Pro, Enterprise, Education and N or LTSC variants |
| Exclusions | x86, ARM, Windows Server, older Windows 10 and locked S mode are outside this package target |
| Runtime | The portable folder includes Python and Qt components; a separate Python installation is unnecessary |
| Collection | Windows PowerShell 5.1 and the required Windows components, with permission to read the selected sources |
| Internet | Optional AI only; the diagnostic engine, examples and reports operate offline |
| Storage | Allow space for the complete program plus cases and exports; a case can reach 256 MiB |

Target compatibility is broader than the observed test coverage. A complete edition and build matrix has not been certified. Missing Windows features or access can limit collection without preventing offline case analysis. Supported attribution is conservative desktop Win32 TCP IPv4 or IPv6; shared hosts, UDP, IPsec, VPN and third-party filters can remain unresolved.

## 3 Verify and open the package

Use the complete ZIP identified by the supplied build record. Compare its SHA256 with the supplied SHA256SUMS through a separately trusted copy of the record. A checksum detects changed bytes; it does not establish a publisher's identity. This release candidate is unsigned.

Keep FirewallAssistant.exe, wfdiag.exe, _internal, examples, docs, notices and build-manifest.json together. Run from the extracted folder, not from inside the ZIP. Do not mix files from different candidates. If Windows protection blocks an executable, retain the message and consult the person supplying the package; do not disable protection or replace individual DLLs.

The desktop opens with AI and recent history off. Initial startup does not collect evidence, contact a provider or launch the application you want to investigate.

## 4 Prepare the investigation

Record the failing application's name, when the failure happened and the expected destination or service. Obtain the correct executable, service port, approved peer and business purpose from the application owner. A connection problem can have causes outside Windows Firewall.

Start investigation checks Windows access before collecting. If Windows denies blocking-event logs, choose Request Windows permission to launch a separate read-only collector through the normal Windows consent prompt, Continue with limited evidence, or Cancel. The GUI and AI stay at normal permissions. Check access only and technical details remain available under Manual steps, time window and access details.

## 5 Collect or open evidence

Start investigation collects and analyzes in sequence. The default lookback is10 minutes; change it to1–60 minutes under Manual steps, time window and access details if needed. Separate Collect local evidence and Analyze collected case buttons are available for manual work. The event window ends when actual collection begins, so time spent reading firewall rules does not exclude the earlier failed attempt.

When access is denied, Ask Windows for permission to collect is also available from the results. Windows may display wfdiag.exe from the verified application folder and request administrator consent or credentials. Enter credentials only into Windows, never the app or AI chat. A cancelled prompt leaves existing results intact. The collector returns evidence to a new private folder and the normal GUI analyzes it. Cancel requests cooperative cleanup; wait for its confirmed outcome before treating output as finished.

Collection reads host/network metadata, ActiveStore profiles/rules and existing Security events5157/5152. It does not enable auditing, change firewall rules, send test traffic or launch the failing application. Administrator permission allows a read attempt; managed restrictions can still deny it. System audit failure flags are observed when permitted; per-user audit policies may differ. Recording is never enabled automatically. Permission cannot create past events. If recording was disabled, an authorized administrator must separately approve any recording change before a new failure is reproduced and collected.

Fixed collector scripts run in application-owned PowerShell child processes using process-only RemoteSigned when no stricter explicit local policy is configured. Machine and user settings are not changed; Group Policy still takes precedence. Collector and helper contents are checked against this engine and held against replacement during use. Internet-marked unsigned scripts or restrictive organizational policies may still be refused. Obtain an approved signed setup rather than removing protection.

Alternatively, choose Open case folder. Select the folder containing manifest.json and all original source files, or an analysis folder containing analysis.json. The application validates the content and hashes. A parent folder without these entry files is not a case. Existing files are never silently overwritten.

## 6 General and specific analysis

General review requires no connection details; the technical form is hidden by default. To investigate one verified TCP connection, enable Focus on one application's connection and supply its executable, direction, actual network profile, peer addresses or CIDRs, service port and purpose. Confirm that you selected the correct executable only after checking it.

For an outbound client, the service port is remote. For an inbound service, it is local. Do not copy an observed ephemeral client port into the intended service port. Broad peers, guessed identities or all-profile defaults cannot establish a narrow proposal. Changing intent makes the previous result stale; reanalyze it before requesting a proposal.

For a browser reaching a website, choose App connects to a website or server. Other computers connect to this app is for a local listening service. The peer must describe the real connection; a DNS server address is not automatically a website's destination. If you do not know the details, use general review rather than entering arbitrary values.

## 7 Read findings and evidence

Review diagnostic category, evidence grade, relevance and source completeness separately. A candidate matching rule is not automatically the cause. A current policy snapshot does not prove what policy existed at the time of an older event. Missing events do not prove that a computer is secure or that the application worked.

Findings distinguish explicit blocks, likely default-policy blocks, profile or managed-policy issues, unresolved WFP causes, evidence gaps and absence of relevant events. Unsupported fields remain uncertain. Native collection can finish with an incomplete case; inspect its source states and limitations before interpreting a result.

The result opens with a plain explanation and next step. Access denied means the blocking log was unreadable; it does not identify a blocked application. No matching event is shown only when the event source was actually readable. Disabled or unverified recording and a time-window mismatch can explain missing events. Show technical collection details reveals the underlying source states without replacing that explanation.

The interface displays findings and detail rows in bounded pages. Search and filters cover the loaded page, up to 500 findings, not the entire case. Use the page controls to inspect more results. Sensitive local details stay hidden until deliberately revealed. Imported text is displayed as text, not executable markup or links.

## 8 Proposals and responsible changes

A proposal is nonexecuting JSON generated by the deterministic engine for independent review. It is available only when the engine's evidence and confirmed intent meet its eligibility rules. The application and assistant cannot apply it as a firewall rule.

An additional local allow rule does not override an explicit block in this product's scope. Managed policy belongs to its policy owner. Read refusal reasons and involve the responsible administrator. Never broaden peers, profiles, identities or ports merely to obtain a proposal.

## 9 Export and compare

Case and comparison pickers start in your work folder when it exists. Export opens in the verified private work folder with a fresh suggested filename. You can choose another destination that meets the report's storage requirements.

Export a share report for a redacted derivative, or deliberately export a full report to a verified private location. Full reports contain sensitive local information. Review share reports before disclosure; redaction cannot guarantee anonymity. Reports are static offline HTML or JSON without scripts or remote assets.

Exports use the complete validated original analysis, including findings beyond the visible page. JSON output is capped at 128 MiB and HTML at 256 MiB. Over-budget or cancelled exports fail as a whole rather than silently exporting an incomplete report. Existing output files remain unchanged.

In Compare, choose two saved analysis results, such as analysis.json. Selections are validated before comparison. network.json, rules.json and manifest.json are raw case files and cannot be compared as analyses. For training, select the bundled expected-analysis.json twice; an unchanged result is expected. For a real before/after investigation, use analyses from the two actual captures. Fewer blocking events does not establish that a repair succeeded.

## 10 Connect the optional assistant

Open AI Assistant, choose Enable AI, select a provider and model, paste that provider's key into the masked field, then choose Connect & test. Leave Remember on this Windows account off for a session-only key. A valid synthetic provider reply is required before Connected appears.

Google Gemini 3.5 Flash-Lite is the current low-latency chat default. Gemini 3.8 Flash is separately selectable and showed intermittent timeouts during development testing. OpenAI and Anthropic adapters have offline contract coverage; live operation with those providers is unverified in this candidate. Model access and quotas depend on your account. No key or free service entitlement is supplied with the software.

Enter keys only in the masked key field, never in a chat message, report or source file. Use remembered key loads only this app's credential for the selected provider; connect to verify it. Forget key removes that app credential. Provider revocation is separate. Storage failure never falls back to a plaintext key file.

## 11 Chat and application actions

Type a question or task and press Enter or Send. Shift Enter adds a line. Try Open the example, Explain my findings, Check this computer or Export a share report. App actions and their actual outcomes appear in the conversation. Case chooser and comparison dialogs still need your input.

The assistant can navigate, inspect redacted findings, check access, collect and analyze evidence, select a current finding, export reports, compare chosen analyses and request an eligible engine proposal. It uses the same services and current permissions as the rest of the app. The engine alone establishes diagnostic findings and proposal eligibility.

The assistant cannot run arbitrary computer commands, request administrator elevation, access unrelated credentials, upload raw cases, alter findings, apply rules or change Windows settings. Only your explicit Windows-permission action starts the separate administrator collector. Provider text is advisory; verify it against the engine result and visible action receipts.

Your messages and redacted app summaries go to the selected provider with up to five recent exchanges for continuity. Provider retention, processing and charges apply. Do not send confidential information your organization forbids the provider to process. Redaction reduces exposure but does not guarantee anonymity.

Stop cancels the current request and assistant-owned app operation. Completed local actions remain. New chat clears conversation memory; Disable AI also clears session keys. Remembered credentials remain until Forget. Cancellation and timeouts do not prove that provider processing or charges stopped.

Details shows the last redacted request without authorization headers, safe request outcome and token counts when available. A message allows up to three provider calls and six app actions. There is no application session-request quota. Reset request counter changes only the display, not provider usage. OpenAI and Gemini use provider-default output allowances; Anthropic requires a value and uses the model maximum. Provider account quotas, context/output limits, rate limits and charges still apply; paid access is not unlimited service. Technical time, response-size and app-action limits remain. There is no automatic retry, provider fallback, account polling or background AI request.

## 12 Settings and local data

Choose Light, Dark, System or High contrast appearance in Settings. Recent history is optional and off by default. When enabled, explicitly named entries are capped at 20 and files are revalidated when reopened. Clear history removes the index, not cases or exports. Changing the work location neither migrates nor deletes old data.

The default application location is the current user's local application data directory under WFDiag-FirewallAssistant. A selected work location must pass local private-storage checks. Cases, analyses, job requests and exports can persist until you remove them deliberately. The application installs no cleanup service, automatic updater, telemetry or startup task.

Clear diagnostic log buffer works while idle and removes only the bounded current or last-job stderr buffer in memory. Conversation is memory-only; the application saves no transcript to disk. Windows, the provider or user-created screenshots can have separate retention. Python memory erasure is not guaranteed.

## 13 Troubleshooting

| Situation | What to do |
|---|---|
| Nothing opens or engine is missing | Restore the complete matching package, preserve any support code and check the supplied checksum; never mix individual EXEs or DLLs |
| No case found | Select the actual folder containing manifest.json or analysis.json, with its original related files |
| Access denied | Review preflight and involve an authorized administrator; offline imported analysis remains available |
| Script policy refused | Follow approved signing or organizational policy; the app does not change persistent settings or remove Internet markings |
| Incomplete, capped or cancelled | Preserve originals and source states; obtain missing authorized evidence in a fresh run |
| No relevant events | Check timing, auditing, identity and completeness; absence is not a health verdict |
| Proposal unavailable | Read engine refusal reasons; confirm intent and policy ownership, then reanalyze if appropriate |
| AI authentication, quota or timeout error | Check the selected account privately, wait or deliberately retry; diagnostics still work with AI off |

Keep version, Windows edition and full build, operation, time and safe error code when reporting a problem. Never post keys, raw cases, full reports or private logs publicly. Use the human review guide supplied with this candidate to collect the requested outputs.

## 14 Upgrade and remove

Close jobs and the app before changing program files. Extract a new candidate to a separate folder and keep the previous one until verified. Do not mix versions or assume old analyses are automatically migrated. Preserve evidence and review schema or engine-version refusals.

To remove the application, review the program folder, application data, work locations, cases, analyses and exports separately. Forget remembered keys through the app before removal, or use an authorized Windows credential-management procedure for only its exact provider targets. Deleting the program does not revoke a key or remove saved evidence. There is no automatic retention timer.

## 15 Source and support

Original project code is MIT licensed, copyright 2026 ViRuS. Bundled Python, Qt, PySide, HTTPX and other dependencies retain their separate terms and notices. The source package includes dependency locks and build instructions. Review Qt source and replacement obligations before distributing binaries; a source license does not relicense dependencies.

The candidate remains local pending owner human review. Official project repository, release download and issue-reporting addresses will be confirmed during the later authorized publication. The supplied author profile links identify the author; they are not a fabricated project release URL.

## Appendix A Administrator CLI

Open a terminal in the complete extracted program folder. These example commands use bundled synthetic data and fresh output names. Choose an existing allowed local parent and retain every original file.

```powershell
.\wfdiag.exe --help
.\wfdiag.exe --version
.\wfdiag.exe report --analysis .\examples\expected-analysis.json --mode share --out .\share-example.html
```

The six user operations are doctor, collect, analyze, report, propose and compare. Use each operation's --help for its exact parameters. General analyze needs a bundle and new output directory. Specific analyze also needs a validated intent JSON. Report accepts share or full and a new HTML or JSON destination. Propose requires analysis, finding ID, confirmed intent and a new JSON output. Compare requires Before and After analyses and a new output file.

| Exit code | Meaning |
|---|---|
| 0 | Operation completed; this does not mean secure, repaired or fully evidenced |
| 2 | Invalid or refused input or output |
| 3 | Unsupported or unavailable capability |
| 4 | Access denied or private output unavailable |
| 5 | Incomplete or cancelled |
| 6 | Internal, worker or output-validation failure |

A doctor report can be generated while its readiness exit code reports missing access. The GUI displays that validated report. A finalized incomplete capture may be analyzed, but an interrupted folder with an .incomplete marker is not a completed case.

## Appendix B Candidate publication record

| Detail | Record for this edition |
|---|---|
| Version | Desktop label V1.0. Package metadata 1.0.0rc1. Handbook revision 9 November 2026 |
| Local identity | Exact source revision, file inventory and executable identities are in the accompanying build-manifest.json and build record |
| Asset | FirewallAssistant-V1.0-RC1-windows-x64.zip; GUI FirewallAssistant.exe and CLI wfdiag.exe |
| Integrity | Exact SHA256 values are supplied in SHA256SUMS; candidate is unsigned and no signer is claimed |
| Observed Windows | Development host Windows 11 x64 build 22621.4317; earlier evaluation startup observed by owner on Windows 10 Pro 22H2 build 19045.6466; not an all-build certification |
| Native access | Normal account reads policy but Security events are denied. Actual Windows consent collection read that source successfully with zero matching events; system5152/5157 failure audit flags were disabled. GUI remained non-admin; no settings changed. Full ground-truth coverage remains unverified |
| AI evidence | Google Flash-Lite live synthetic source chat and app actions observed; exact packaged results are in the supplied build record; other-provider live validation unperformed |
| Privacy | Local case and output controls implemented; no raw host evidence was uploaded in development tests; redaction is not anonymity |
| Public URLs | Not published; owner human review and later explicit GitHub authorization are pending |
| Release decision | Release candidate only; owner final human review and stable release decision remain pending |

The supplied build result and known-limitations file identify which procedures ran on the exact package. Unperformed or blocked validation is not passed. Changes to capabilities, models, labels or privacy behavior require a corresponding handbook update.

## Appendix C Official references

Microsoft Windows Firewall overview: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/

Microsoft PowerShell execution policies: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1

Google model and account setup: https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite and https://ai.google.dev/gemini-api/docs/api-key

OpenAI API setup: https://developers.openai.com/api/docs/quickstart

Anthropic setup: https://platform.claude.com/docs/en/get-started
