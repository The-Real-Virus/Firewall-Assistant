# Chat with the AI Assistant

AI is optional and starts off every time. Diagnostics, the GUI/CLI, examples and reports work
without it. AI needs your own provider account, key with model access and internet connection.
Google Gemini3.5 Flash-Lite is the default chat model. Source live connection, conversation
and actual application actions have been observed; see the build record for packaged checks.
OpenAI and Claude live operation remains unverified. Gemini3.8 is separately selectable and
has shown timeouts. Changing models is deliberate; there is no automatic fallback.

1. Open **AI Assistant** and choose **Enable AI**.
2. Choose Google Gemini, OpenAI or Anthropic Claude. Paste that provider's key in the masked
   field. Leave **Remember on this Windows account** off for a session-only connection.
3. Choose **Connect & test**. This sends one small synthetic request. Only a valid provider
   reply changes the label to **Connected**; saving a key alone never establishes a connection.
4. Type a message and press **Enter** or **Send**. **Shift Enter** adds a line. Try “Check this
   computer”, “Explain my findings”, “Open the example” or “Export a share report”.
5. Each app action and outcome appears in chat. Dialogs still need your input. The assistant
   uses the same diagnostic services and current Windows permissions as the app's buttons.

It can check access, collect existing evidence, analyze/open cases, inspect/select findings,
export reports, prepare eligible engine proposals and compare selected Before/After analyses.
It cannot change engine findings or Windows/firewall/audit settings, execute arbitrary commands,
elevate, access unrelated credentials or upload raw cases. Proposals are nonexecuting review JSON.
Missing access and incomplete evidence remain visible. Connected verifies an API exchange,
not a diagnosis or permission to change Windows.

Your message and redacted app summaries go to the selected provider with at most five recent
exchanges for continuity. Provider policies and charges apply, including possible retention or
use of unpaid-service data. Do not paste secrets/confidential data into chat. Redaction reduces
exposure; it cannot guarantee anonymity. Keys belong only in the masked field.

**Stop** cancels the request and assistant-owned app operation; completed local actions remain.
Cancellation/timeouts cannot guarantee that provider processing/billing stops. No automatic
retry, fallback, model lookup, account polling or background API request occurs. **New chat**
clears conversation memory. Changing provider/case context clears sent history. **Disable AI**
also clears session keys. The application saves no conversation to disk.

**Connection settings** changes provider/key. **Test connection** rechecks the session key.
**Use remembered key** deliberately loads this app's credential for the selected provider;
then connect to verify it. **Forget key** removes that credential, not the provider's key.
Revoke compromised keys with their provider. Storage failure never falls back to plaintext.

**Details** shows the last redacted wire request (without authorization headers), request count
and metadata-only outcome/token usage when known. Each Send allows up to three provider calls
and six app actions. There is no application session-request ceiling. The counter can be reset
without changing provider usage. OpenAI and Gemini use provider-default output allowances;
Anthropic requires max_tokens, set to Haiku4.5's documented64000 maximum. Provider account
quotas, rate/context/output limits and charges still apply. Timeouts, bounded responses and
validated app-action limits remain; a paid account does not promise unlimited service.
Gemini uses MINIMAL thinking for3.5 Flash-Lite and LOW for3.8. Final cost may be unknown.

For authentication, model access, quota or network errors, follow the short message shown and
check your account privately. Core diagnostics remain available. See providers.md for exact
model/API references and offline/live validation status.
