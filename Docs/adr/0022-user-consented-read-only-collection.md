# User consent for read only administrator collection

Owner approved both usability and permission plans on8 November2026. Current session diagnosis
using native EvtQuery returned ERROR_ACCESS_DENIED5 with a non-admin token; read-only audit
query was unavailable. This confirms a Windows access restriction in that session, not a
successful query returning no events. No event contents were logged by the probe.

The GUI offers a deliberate Windows-permission action. ShellExecuteExW with runas launches only
the verified absolute sibling wfdiag.exe, with fixed permission-collect/minutes/output arguments.
Windows supplies the consent or administrator-credential prompt. The GUI and AI retain their
normal token. No AI action can invoke this path. No arbitrary command, input script, request
file or operation is passed to the administrator process. Credentials never enter the app/chat.

Before launch the GUI creates a new empty private UUID output slot. The helper verifies that
both slot and parent have the same exact protected operator/Admins/System DACL. This supports
an administrator credential distinct from the requesting user without changing existing ACLs
or weakening normal output ownership checks. Nonempty slots, links and mismatched ACLs are
refused. Higher-privilege data is intentionally returned to the requesting user's private slot
after Windows consent. Same-account native slot validation passes; native cross-account
acceptance remains unperformed until actual credentials/consent are available.

The helper can only collect existing host/network/policy/Security evidence. A derived cancel
flag grants only cancellation, and the helper has a420-second cooperative deadline plus each
existing bounded collector deadline. GUI polls the returned process handle, validates the
entire resulting bundle and version, and analyzes through the ordinary unelevated worker.
Windows refusal/cancellation never becomes success; unknown process cleanup is reported as
unconfirmed. Existing results and interrupted output are retained.

Permission does not create past events or enable auditing. AuditQuerySystemPolicy observes
failure flags without adjusting privileges or changing policy; unavailable observation stays
unknown. Case source codes distinguish observed failure recording settings. Any audit-policy
change requires a separately approved exact action. The event query end is anchored before
slow policy collection so a short lookback still covers the reproduced failure.

No firewall, audit, persistent execution-policy or trust-store change is implemented. Existing
approved process-only RemoteSigned remains limited to fixed hash-pinned collection resources.
Unsigned software must remain labelled unsigned. Exact source/frozen/consent test evidence is
recorded separately; unit doubles do not establish actual UAC or privileged-event acceptance.

Primary references: [ShellExecuteEx process handles](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfoa),
[Windows PowerShell event access](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1),
[read-only audit query](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy).
