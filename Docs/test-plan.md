# Verification plan

Synthetic unit/contract/AI-contract/GUI-shell checks have run. Native/integrated acceptance remains blocked; A00 and GUI direction are approved. Each case record must add fixture/capture hash, source revision, exact platform, input and ground truth, expected finding, expected completeness, expected eligibility, actual result, command and evidence path. Completeness is derived from source status; it is not inferred from the finding category.

| ID | Scenario | Ground truth to construct | Expected observation and proposal behavior | Work / validation |
|---|---|---|---|---|
| T01 | inbound default block | Known complete default-block flow with independently verified intent | DEFAULT_BLOCK; eligible only with all prerequisites | in_progress / full acceptance blocked |
| T02 | explicit block | Known explicit blocking rule and conflicting allow | EXPLICIT_BLOCK; no add-allow proposal | in_progress / full acceptance blocked |
| T03 | disabled rule | A disabled rule otherwise matches | Disabled rule cannot explain effective match; conservative attribution | in_progress / full acceptance blocked |
| T04 | profile mismatch | Known active/intended profile difference | PROFILE_MISMATCH; no guessed profile expansion | in_progress / full acceptance blocked |
| T05 | outbound client and ephemeral local port | Known remote service port and changing local ports | DEFAULT_BLOCK if supported; remote service port only | in_progress / full acceptance blocked |
| T06 | IPv6 | Known IPv6 flow and matching address family | Correct IPv6 normalization and conservative matching | in_progress / full acceptance blocked |
| T07 | multiple candidate rules | Two complete indirect candidate matches | Preserve all candidates; no arbitrary first cause | in_progress / full acceptance blocked |
| T08 | missing auditing | Known unavailable evidence source | EVIDENCE_GAP; incomplete; no proposal | in_progress / full acceptance blocked |
| T09 | access denied | Known denied required source | Distinct denial; incomplete; no empty success | in_progress / full acceptance blocked |
| T10 | no relevant event | Complete evidence window with no intended flow event | NO_RELEVANT_EVENT; no healthy-host claim or proposal | in_progress / full acceptance blocked |
| T11 | stale policy snapshot | Known policy change after event | Historical attribution uncertain; no proposal | in_progress / full acceptance blocked |
| T12 | unresolved native application path | Unmapped device path | Preserve raw path/unknown identity; no proposal | in_progress / full acceptance blocked |
| T13 | PID reuse or exited process | Historical PID differs from current process identity | Current PID cannot confirm historical identity; no identity-based eligibility | in_progress / full acceptance blocked |
| T14 | localized display text | Same XML names with localized display strings | Same normalized evidence; no display-message parsing | in_progress / full acceptance blocked |
| T15 | missing Filter Origin | Event without resolvable origin | Candidate/unknown attribution only; no false confirmation | in_progress / full acceptance blocked |
| T16 | malformed or oversized input | Invalid XML/JSON/enums/depth/actual bytes | Fail closed or explicit incomplete per source contract; no proposal | in_progress / full acceptance blocked |
| T17 | HTML injection | Markup in imported values | Escaped static report/plain text UI; no execution or fetch | in_progress / full acceptance blocked |
| T18 | path traversal or reparse redirection | Hostile manifest/output/reparse paths | Reject unsafe inputs and preserve existing output | in_progress / full acceptance blocked |
| T19 | managed policy or disabled local merge | Known GPO/MDM ownership restriction | LOCAL_RULE_MERGE_RESTRICTED or supported policy explanation; owner route | in_progress / full acceptance blocked |
| T20 | unsupported service/IPsec/third party filter | Known unevaluated match condition | Unknown/unresolved condition; no proposal | in_progress / full acceptance blocked |
| T21 | interrupted or truncated capture | Known cap, timeout or cancellation | Incomplete/quarantined; never completed badge | in_progress / full acceptance blocked |
| T22 | redaction canary | Planted secrets plus identity/path/address free text | No leak in share artifact/AI bytes; block unsafe export/send | in_progress / full acceptance blocked |
| T23 | clean machine packaged startup | Exact ZIP on clean target without developer runtimes | GUI/CLI/jobs/examples work; separate AI-off/on evidence | in_progress / blocked (local evaluation/safe CLI/wheel checked; clean target/GUI acceptance missing) |
| T24 | before and after comparison | Two complete analyses plus deliberately missing later traffic | Preserve ordering/context/uncertainty; fewer events is not repair proof | in_progress / blocked (source pure/service/QProcess comparison checks pass; native full acceptance missing) |

## Levels and gates

Synthetic unit/property/contract checks verify pure expected outcomes. Real native captures verify assumptions and collection. Windows ACL/reparse/process lifetime, standard/elevated access, Narrator, scaling, package and performance tests require authorized native evidence. GUI/CLI parity compares all T01–T24 applicable fixture outcomes; native T23 still needs a clean machine. Empty/skipped suites cannot pass a gate.

The actual5 November819-test source run is mapped to24 scenario rows in
evidence/source-scenario-coverage-20261105.json. These are actual passing component observations;
all full-scenario acceptances remain blocked. T23 repair component tests do not establish a clean
machine or frozen GUI launch. The local package's separate actual checks are indexed in
evidence/local-evaluation-20261105.md. No native pass is derived from source coverage counts.

Core checks after setup: ruff check; ruff format --check; mypy src; pytest tests/unit tests/contract; schema export drift; dependency audit; installed wheel/resource smoke. Add real worker round trips and GUI workflows, hostile protocol frames, stale IDs, crash/cancel/EOF/orphan ownership, redaction refusal and no-network guards. No privileged integration suite runs before A01.

GUI budgets on 4 vCPU/8 GiB target: 9/10 cold launches <=3 s; p95 <=100 ms for 100 interactions; no observed event-loop stall >200 ms; cancel feedback <=250 ms; idle <=1% CPU over 60 s and <=250 MiB working set; combined peak <=900 MiB; engine <=60 s/512 MiB for 100000 records; 20 open/close cycles retained growth <=50 MiB; <=10 visible progress updates/s. Preserve raw samples and measurement method.

Accessibility: both themes, high contrast OS palette, keyboard/focus, actual Narrator, minimum 1000x700 logical pixels, 100/125/150/200% scaling, large text, mixed-DPI monitors and reduced motion. Text contrast >=4.5:1, large text and essential controls/focus >=3:1. Offscreen tests cannot pass native accessibility.

AI: >=30 distinct versioned cases for every adapter using adversarial canned responses. Cover every finding category, general help, incompleteness, IPv6, unresolved identity, injection in inputs/outputs, encoded identifiers, canaries, malformed schemas, redirects, cross-host keys, compressed oversize, slow streams, timeouts, cancellation, disable/close races, unavailable imports/keys/settings/DNS/network and unchanged engine bytes. A07 approves >=10 representative live cases per advertised model plus one packaging smoke request per model; real reviewer scores factual fidelity, uncertainty, references and forbidden claims. Fake transports never pass live checks.

Native offline journey: no key/no internet, launch package, skip AI, example, permitted collect/import, analyze, findings/proposal/refusals, export, compare. Native configured journey: masked owned key, reviewed synthetic send, labelled validated answer, disable, continue full diagnostics. Observe traffic with process attribution, not unrelated Windows background traffic.

Retest affected gates after code, lock, prompt/schema/model, package, target build or handbook changes. Pilot default >=2 weeks with scenario coverage, real endpoints and independent Windows practitioner review; elapsed time alone never passes G7.
