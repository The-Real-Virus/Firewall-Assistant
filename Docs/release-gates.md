# Release gates

G1 local technical contracts passed on4 November2026 with recorded postcommit tests,
schema and installed/frozen-safe contract evidence. G0 and G2–G8 remain unpassed. A local
evaluation is not release acceptance. Gate states are pending/pass/fail/blocked; work and
validation stay separate. A phase is complete only when all required acceptance has evidence.

| Gate | Integrated acceptance | State | Current blocker |
|---|---|---|---|
| G0 | Scope, authorized target lab, optional AI scope/consent, desktop design decision | blocked | A00/U02 approved; owner VM facts supplied, but disposable isolated lab/snapshot/private peer and exact native packet unavailable |
| G1 | Schemas, CLI, desktop jobs/shared services and AI contracts | pass |128 postcommit contract checks,22-schema drift, actual installed/frozen-safe CLI/resources; see G1 evidence record |
| G2 | Native policy/events and real GUI collection with AI off | blocked | No authorized lab or captures |
| G3 | Deterministic findings/proposals, negative tests, CLI/GUI parity and AI independence | blocked | Extensive local fixture evidence exists; native ground truth and complete parity still required |
| G4 | Hostile inputs, privacy, ACLs, subprocess/IPC/cancellation, credentials and AI transport policy | blocked | Local hostile-input/real frozen IPC checks exist; comprehensive native ACL/credential, live transport and independent security review pending |
| G5 | Integrated GUI/CLI ZIP, wheel/resources, clean machine AI-off/on tests | blocked | Actual development-host GUI/startup/fixture workers/ZIP/wheel checks pass; clean-target/full privacy/AI-on acceptance missing |
| G6 | Native compatibility, measured engine/GUI/AI budgets and accessibility/outages | blocked | Development100k measurements exist;205ms resize miss retained. Reference-VM/matrix/frozen budgets/accessibility evidence incomplete |
| G7 | Independent review, approved real pilot and AI factual/live evaluation | blocked | No reviewer, pilot or A07 live evidence |
| G8 | Exact candidate decision, valid G0–G7, release artifacts and actual owner signoff | blocked | No candidate or A05 decision |

Record decisions with docs/evidence/templates/gate-record.schema.json. A pass requires actual evidence, revision/platform/artifact identity and no missing prerequisites. Implementation status never substitutes for validation. Preserve failed/blocked observations and invalidate stale results after changes.

A00 covers routine local development/dependency setup only. U02 design approval precedes polishing every screen. A01 identifies VM, snapshot, private peer, exact privileged commands, data scope and cleanup. A02 covers expanded access beyond the packet. A03 approves exact signing identity/candidates. A04 approves pilot endpoints/retention/reviewer. A05 accepts/rejects exact candidate. A06 is dormant: owner publishes manually, so no external publication is in this task. A07 separately approves exact provider/model/live fixtures, calls, caps, cost and local credential entry.

No untriaged critical/high defect may remain at release. Lower severity exceptions require owner, impact, rationale and target version. G8 requires actual owner decision; do not pre-label a development/evaluation build as production ready.
