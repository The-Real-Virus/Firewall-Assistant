# Conversational application assistant

Owner7 November2026 supersedes the explanation-only form and per-message approval workflow.
The desktop now uses AssistantSession, assistant-v2.txt and ApplicationTools. Earlier AiSession,
explanation contracts/catalog and live-fixture packets remain compatibility/history evidence;
they are not the new chat protocol or proof of live model operation.

AI imports lazily after Enable AI. AiController owns the async network worker. ApplicationTools
bridges validated AppAction values to Qt's main thread; existing WindowController/QProcess/shared
services do the work. The CLI worker protocol still has six operations and no AI dependency.
The deterministic engine alone determines findings, grades, completeness, proposal eligibility
and comparisons. Model prose never writes engine records or establishes diagnostic facts.

Structured replies contain a plain message and at most three typed app actions. Twelve action
names accept only their relevant bounded arguments. No arbitrary command/path/file-read/URL/
credential/firewall tool exists. Dispatch reports actual completion, failure or cancellation.
Synthetic examples stay labelled and cannot masquerade as real cases or produce real proposals.
Current-user services use private storage and fresh UUID output names without overwrites.

Connection needs a synthetic successful exchange bound to provider/model/current key. Each Send
permits three model rounds/six app actions. Repeated collection/analysis/preflight/chooser actions
are withheld within a turn. A final cap states the limit instead of claiming a planned action
completed. Unavailable/cancelled local/worker operations propagate through the gateway.

Messages are normalized/redacted. Snapshots allowlist engine enums, source states, safe codes,
counts and random finding references. Raw cases, paths, addresses, rule text and imported prose
are never sent. A bounded private identity index includes off-page held-analysis data. Pasted
paths/links/tokens are conservatively hidden; unresolved/encoded disclosure fails closed.
Responses are escaped plain text with links disabled. Redaction does not guarantee anonymity.

Five exchanges/16KiB memory-only history support follow-ups. Context/provider changes clear
history; Disable/New chat clears conversation. At most80 display messages and200 request
metadata records remain in memory. Records contain ID/time/provider/model/safe outcome/duration/
usage, no bodies/keys/headers/local paths. Details exposes the last redacted body. No disk chat,
telemetry, startup request, automatic retry, provider fallback or account polling exists.

Fixed HTTPS endpoints are api.openai.com/v1/responses (store false), api.anthropic.com/v1/messages
and generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent. TLS and
hostname verification, trust_env false, bounded decompression, no redirects and60-second total
deadline remain. No provider SDK/custom host/ambient proxy or CA override is accepted.200
metadata records are retained in memory; there is no session request quota. Reset clears only
the displayed counter, not provider usage. Provider limits and charges apply.

API review8 November: raw Claude schema omits unsupported numeric constraints while strict
local validation enforces them. OpenAI/Gemini omit optional output caps. Anthropic requires
max_tokens, set to Haiku4.5 maximum64000. Gemini uses MINIMAL thinking for3.5 Flash-Lite and
LOW for3.8, without candidateCount. Transport/response/action bounds remain. See providers.md
for primary references and exact live evidence. Development test approvals separately bound
synthetic-only calls; they do not impose an app quota. AI never triggers the UAC collector.

Keys are masked/session-only by default. Explicit remember/load/forget touches only this app's
selected-provider Windows credential target, never enumerates credentials or falls back to
plaintext. Remembered keys survive Disable until Forget; provider revocation is separate.
Provider retention, processing and billing depend on the account; no zero-retention claim.
