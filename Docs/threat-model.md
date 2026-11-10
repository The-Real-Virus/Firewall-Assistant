# Threat model preparation

Assets: accurate evidence/uncertainty, policy integrity, private cases/exports, API keys, controlled
cloud disclosure, source/release integrity and truthful support claims. Untrusted sources include
all imported fields/files/filenames, intent, worker frames, questions and model replies.

| Threat | Proposed control | Required evidence still blocked |
|---|---|---|
| Script/executable injection | Fixed absolute executables/resources, typed parameters, shell false | Runner/adversarial and native process tests |
| Unsafe path, ADS, reparse/race | Opened-object validation, containment, known files/limits, atomic new outputs | Native ACL/reparse/race assessment |
| XML/JSON/size denial of service | DTD/entity defense, schema/depth/count limits and actual streamed caps | Hostile inputs/property/bounded benchmarks |
| False attribution/overbroad proposal | Complete condition matching, provenance, uncertainty and refusal gates | T01–T24 ground truth and negative coverage |
| Report/UI injection or disclosure | Escaping/plain text, no URL activation, shared structured/free-text redaction | Canary and visible export tests |
| IPC spoofing/stale completion/orphans | Private job ACLs, version/job/sequence caps, process+result agreement | Real worker crash/cancel/EOF/race tests |
| Key exposure/cross-provider routing | Native scoped credentials, no plaintext/debug bodies, fixed host headers | Sentinel and native WinCred lifecycle tests |
| Cloud context leak/prompt injection | Allowlisted context, final-byte checks, digest-bound review, no tools | Every-adapter adversarial and live reviewer evidence |
| Provider response misleads engine | Immutable engine facts, schema/reference/content validation, separate prose | Before/after byte parity and factual rubric |
| Unsupported release claims | Hash/revision-bound gates and actual owner decisions | Clean targets, review, pilot, exact RC signoff |

Residual risk must be concrete: hashes do not authenticate senders; filesystem races are not
universally eliminated; pseudonyms do not guarantee anonymity; model schemas do not prove truth;
Credential Manager cannot defend a compromised same-user process; cancellation does not erase
provider processing/billing. Independent security review remains blocked.

## Storage implementation observations

Synthetic hostile-bundle tests validate sizes/hashes/counts, unsafe names, hard links, duplicate
JSON properties, invalid encoding and interrupted new-file finalization. Windows component
tests observed denial of concurrent writes while sources were held; these are not target-lab
ACL/reparse validation. Relative child opens and held identities narrow the check/open race.
Directory enumeration and pathname-based output finalization still involve paths. Same-user or
administrator mutation of ancestors remains a residual risk; use protected local storage.

New-directory ACL source uses CreateDirectoryW with a protected inheritable DACL for operator,
Administrators and System, then checks owner, protection and exact ACEs. It refuses impersonation,
existing directories or unverifiable permissions. It changes no existing ACL and does not use
chmod as Windows privacy. Native creation/inheritance/access-denial validation is blocked on A01.
Synthetic SDDL tests do not pass that gate. Collect and private output commands call this
routine in normal operation; synthetic workflow tests explicitly replace the privacy boundary.

## Collector source integration

Fixed host/policy/event scripts, typed resource selection, clean environment and streamed bounded
stdout now exist. A native source cannot select a new executable, script, remote host or command.
Partial/invalid frames, source/count mismatch, time reversal, denied reads and truncation cannot
produce a complete source. Unknown fields/conditions preserve conservative refusal. Source guards
and invented-stream tests pass; native script syntax, source semantics, private ACL acceptance,
real no-mutation baselines and independently reviewed Windows execution remain blocked.

## Packaged engine and local technical details

The GUI checks a bounded manifest/version and sibling CLI bytes/hash in a background preparation
task before creating a packaged job. Its fixed absolute launch and worker protocol/result checks
remain independent. A matching manifest/hash is consistency evidence only; an attacker replacing
the whole trusted program folder can replace both. Protected installation and trusted archive/
publisher verification remain required. Critical runtime DLL integrity and same-user/admin races
are not certified by this single-engine check. Native missing/corrupt/frozen journey acceptance
remains blocked despite source negative tests.

Policy identities/conditions and source-detail text are plain, page bounded and hidden until
Reveal; hidden values do not enter search. Candidate filters do not reinterpret engine findings.
Technical stderr stays in memory, capped1MiB per current/last job; explicit idle cleanup affects
only that buffer. Private job requests/evidence persist separately until the operator's retention
procedure removes selected data. No automatic case deletion or persistent raw-log export exists.
