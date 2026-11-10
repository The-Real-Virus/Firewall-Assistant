# Privacy and retention plan

Core diagnostics stay local. Store raw cases outside Git/source by default in a separately
approved private operator location with real Windows ACL controls. Do not collect credentials,
payloads, unrelated process command lines or browser data. Host/user/path/address/rule/error
fields remain sensitive. Technical stderr is a bounded1MiB memory-only current/last-job buffer,
not a persistent or tamper-proof audit trail. Explicit idle cleanup removes that buffer alone.

Share reports are separate redacted derivatives with random per-report pseudonyms and no reverse
map/raw attachments; unresolved disclosure blocks export. Local full reports require explicit
disclosure acknowledgement. GUI views hide sensitive details until deliberately revealed and
never interpret imported rich text/links. User-chosen outputs are never silently overwritten.

AI is off by default. Enable/connect and each explicit Send authorize the chat task, bounded
follow-up calls and validated app actions. Messages and redacted summaries with up to five recent
exchanges go to the selected provider; Details shows the last redacted body without headers.
No raw evidence upload, background network, telemetry, auto-update or hidden fallback. Keys use
masked local entry, session-only default and optional provider-scoped Windows credential store;
never chat/project/env files. Provider policies/costs require dated review and no zero-retention
promise. Disable and Forget key have distinct effects; revocation is a provider action.
See retention-upgrade-removal.md for exact credential targets, persisted request/preferences
boundaries and separate removal/upgrade/rollback steps. Native lifecycle acceptance stays blocked.

History off by default, opt-in capped20; Clear history removes only the index. Seven-day raw-case
retention is an operator policy proposal, not a cleanup service. Never delete owner-selected
files/exports automatically. Removal guide must separately cover program, cases, analyses,
exports, preferences/logs, conversation and saved provider credentials. No live data collected.

## Implemented report derivative

Pure report rendering now produces full/share HTML and JSON. Share mode constructs a new
allowlisted record. It omits intent, events, rules, network context, source warnings, exact times
and identity data. Fresh aliases retain limited correlation; their reverse map is not serialized.
Unknown refusal strings become a fixed restriction. Planted canary, paths, user/host names, URLs
and IPv4/IPv6 in structured and free-text locations do not survive share exports. Full HTML
escapes injected markup. HTML has no active links, scripts or remote assets and has a restrictive
content policy. This does not guarantee anonymity. CLI/GUI exports use shared services and have
fixture/worker coverage; actual native privacy acceptance is blocked. Browser layout QA was
blocked by Computer Use app approval timing out.

Large exports stream every original finding through those same policies; GUI paging does
not limit exported records. The worker validates every share row without retaining a full
report model in the window. JSON output cap is128MiB; HTML output cap is256MiB for markup
expansion. These output limits do not change case-input caps or permit truncated sharing.
Cancelled/over-budget writes remove staging, keep existing destinations and report failure.
Full HTML/JSON still contains sensitive local evidence. No transcript or AI prose is added.
See ADR0020; source measurements do not establish native private-output/browser acceptance.
