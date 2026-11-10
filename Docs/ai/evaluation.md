# AI evaluation plan

## Local catalog status, 3 November2026

tests/fixtures/ai/evaluation-v1.json is version2026-11-03-r1 and contains43 distinct synthetic
cases. It covers all seven diagnostic categories, IPv6, unresolved identity/protocol, incomplete
capture, unrelated traffic, both glossary topics, injected/fake-system/previous-display questions,
unknown references, schema/size failures, commands, directives, HTML/links, paths/addresses,
canaries, keys and Unicode/URL/base64/hex encodings. Each row records approved context, expected
facts, permitted refs/steps, forbidden claims and a reviewer rubric. Twelve representative scene
IDs are listed as a draft live subset; no live subset is approved by that list.

The complete43-case canned catalog runs through each adapter, exact consent and the shared
transport with HTTPX mock streams. Separate poisoned imported-text checks exercise actual
allowlist construction and unchanged validated analysis bytes on each adapter.142 catalog/
coverage/imported-text checks pass. Expected facts and rubrics are human semantic criteria,
not an exact-word substitute for factual review. These tests measure local handling of invented
responses; they do not measure the accuracy of a live model or satisfy the independent reviewer.

Final regression and evidence updates are recorded in docs/progress.md and private command
records. A07 account access, locally entered credentials, actual provider responses/charges,
packaged smoke, native process-attributed network observations and human evaluation stay blocked.

AQ01–AQ20 are preserved in requirements. AI05 creates >=30 distinct versioned evaluation cases
and exercises the full adversarial canned catalog on every adapter. Each case records approved
context, expected facts, allowed refs/next steps, forbidden claims and reviewer rubric. Include
all engine categories, uncertainty/refusals, managed policy, unsupported flows, hostile schema-
valid prose, identifier encodings and secrets. Engine bytes/semantics stay unchanged by AI.

A07 must identify exact model/provider, synthetic request hashes, at least 10 representative
cases/model plus packaging smoke, attempted call count, token limits, reviewed pricing and
maximum approved spend/allowance, credential entry, data policy and cleanup. No live request
is authorized at A00. Real human factual review is required; schema validity and self-review
are insufficient. Missing key, account access, model or lab is blocked, never a fake pass.

On5 November2026, A07-preparation-20261105.md records39 exact synthetic request bodies
(12 scenes plus one future packaged smoke per provider), current serializer hashes and
rubrics, with blocked live/human outcomes. The offline preparer has no key/send interface.
Input-token/spend/account/runner/candidate/credential/reviewer prerequisites remain unresolved;
this draft is not an approval request or live-test authorization.
