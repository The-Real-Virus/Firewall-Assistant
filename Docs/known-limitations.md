# V1.0 candidate limitations and validation scope

V1.0 Release candidate (1.0.0rc1) is unsigned and local, pending the owner's final human review
and stable release decision. See BUILD-RESULT for exact executable checks. Historical gate
records retain their dated scope; the owner superseded their approval ceremony, not the need
for truthful evidence.

- Target: standard x64 Windows10 1809+ and Windows11 desktop editions, including Home, Pro,
  Enterprise, Education and N/LTSC. The entire edition/build matrix remains unverified. x86,
  ARM, older Windows10, Server, IoT Core and locked S-mode are outside this package target.
- Current non-admin Windows11 build22621.4317 capture completes host1, network17, profiles3
  and rules524. Security events are denied at normal privilege. The explicit user-consented
  read-only collector successfully read that source, with zero matching events and disabled
  system failure audit flags. GUI/AI stayed non-admin; no firewall/audit settings, persistent
  policies or trust changed. Permission does not create past events or override managed controls.
- Fixed collector scripts/helpers are SHA256 checked and read locked. Approved child-process
  RemoteSigned is suppressed for stricter explicit local policies; Group Policy takes precedence.
  Internet-marked unsigned files and managed controls can refuse execution. No markings are removed.
- Native event-direction/identity/time semantics, cross-account elevation, exhaustive no-mutation,
  credentials/privacy and clean-machine behavior across all targets remain unverified. Unknown,
  capped, missing and failed evidence never becomes complete or unrestricted.
- Attribution/proposals focus on constrained desktop Win32 TCP IPv4/IPv6. UDP, shared hosts,
  RPC, AppContainer, service/IPsec/VPN and third-party constraints can remain unresolved.
  Managed/unknown restrictions withhold allow proposals. No proposal execution/apply exists.
- A snapshot is not historical proof. Candidate rules are not confirmed causes. An empty event
  list or fewer later events does not prove health or repair. Confirmed intent matters.
- Search covers the displayed500-row page; exports use the complete validated original. Input
  budgets are128MiB/source and256MiB/case; output limits128MiB JSON and256MiB HTML. Over-budget
  outputs are refused as a whole. Redaction reduces exposure without promising anonymity.
- Source large-case performance observations exist. Complete reference-machine/frozen combined
  resource, DPI, Narrator, keyboard and accessibility certification remain unverified.
- Google3.5 Flash-Lite source live synthetic connection/chat/actions have been observed.
  Google3.8 has one connection success and timeouts. OpenAI/Claude live checks are unavailable.
  Exact packaged live evidence belongs to the accompanying build record. Availability, quota,
  processing and charges can change. No automatic retry or model fallback exists.
- Stop/timeouts cannot guarantee provider processing or charges stop. Disable drops session keys
  and history; remembered credentials require Forget, and provider revocation is separate.
- Broader independent review, pilot, signing and Qt source/replacement/redistribution review remain
  unfinished. Stable release/public URLs await owner review and explicit publication approval.
  No remote, upload, push or publication occurred.

Use Documentation.docx for installation, operation, and troubleshooting.
Failed/blocked evidence is retained privately. Local checks never substitute for missing validation.
