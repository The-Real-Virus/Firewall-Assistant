# Provider verification matrix

| Adapter | Planned API | Exact model/API mapping | Offline contract | Live evidence |
|---|---|---|---|---|
| OpenAI | Responses; text.format JSON schema; store false | gpt-5.4-mini-2026-03-17; provider-default output; reasoning none | pass synthetic fixtures only | blocked A07/access |
| Anthropic | Messages; output_config.format JSON schema | claude-haiku-4-5-20251001; version2023-06-01; required max_tokens64000 | pass synthetic fixtures only | blocked A07/access |
| Google default | generateContent; responseJsonSchema | gemini-3.5-flash-lite; v1beta; provider-default output; MINIMAL thinking | pass synthetic fixtures | source live synthetic connection/chat/follow-up/app export observed; see exact packaged record |
| Google alternative | generateContent; responseJsonSchema | gemini-3.8-flash; v1beta; provider-default output; LOW thinking; no candidateCount | pass synthetic fixtures | one connection success and timeouts; full chat acceptance unverified |

Documentation review date:8 November2026. The desktop uses assistant-v2 structured chat/actions;
the earlier explanation/live fixtures are historical. Current chat has no session-request quota.
OpenAI/Gemini omit optional output-token caps. Anthropic requires max_tokens; Haiku4.5 uses its
documented64000 maximum. Model/account/provider limits still apply. Development live tests
are separately capped by their approval and do not impose an application quota. Raw numeric
schema constraints and technical time/response/action bounds are enforced locally; Gemini
candidateCount is omitted.

Output mapping references: [Gemini generation settings](https://ai.google.dev/api/generate-content),
[Anthropic Haiku4.5 maximum](https://platform.claude.com/docs/en/models/haiku-4-5/overview),
[OpenAI optional output limit](https://developers.openai.com/api/reference/resources/responses/methods/create).

Legacy explanation mapping review:3 November2026. These are documented candidates tested with invented
responses, not advertised live-verified combinations. The shipped providers-v1.json records exact
routes, versions, output mappings, prompt/schema versions, dated pricing observations and policy
links. No cost estimation is enabled; actual account access and final charges remain unknown.
GPT4.1mini was excluded after its current page marked it deprecated. Haiku4.5 is currently listed
active legacy; recheck its lifecycle before A07 and release. No silent upgrade/catalog lookup or
fallback occurs. Requested three-provider completion still requires all three live evaluations.

Reviewed primary sources:

- [OpenAI model and snapshot](https://developers.openai.com/api/docs/models/gpt-5.4-mini),
  [structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs),
  [data controls](https://developers.openai.com/api/docs/guides/your-data).
- [Anthropic model](https://platform.claude.com/docs/en/models/haiku-4-5/overview),
  [structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs),
  [API versions](https://platform.claude.com/docs/en/api/versioning),
  [data handling](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention).
- [Google model](https://aistudio.google.com/docs/models/gemini-3.8-flash),
  [generateContent REST](https://aistudio.google.com/api-reference/generate-content/generate-content),
  [pricing](https://aistudio.google.com/docs/pricing),
  [terms](https://ai.google.dev/gemini-api/terms).

Responses state storage is disabled for OpenAI; monitoring/caching/account terms still apply.
Anthropic retention and schema caching depend on the applicable arrangements. Google unpaid services can use input/output for improvement and human review. The new chat
sends user messages and redacted app summaries after explicit Connect/Send; account tier is not
inferred. Use only information your organization permits the selected provider to process. No zero-retention,
permanent-free-service or compliance claim is made. Keys are entered locally, never in chat.

Current compatibility sources checked7 November2026:
- [Claude raw schema limitations](https://platform.claude.com/docs/en/build-with-claude/structured-outputs).
- [Gemini3.8 migration and candidateCount](https://ai.google.dev/gemini-api/docs/latest-model).
- [Gemini Generate Content thinking](https://ai.google.dev/gemini-api/docs/generate-content/thinking).

These references explain request mappings. Live source observations do not establish
other-provider access, all-model reliability, pricing or exact packaged acceptance.
