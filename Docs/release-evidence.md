# Local release evidence verifier

scripts/verify_release_evidence.py performs bounded schema, source identity and SHA256
consistency checks. It does not authenticate human testimony, evaluate the truth of a screenshot,
grant A05, sign files, upload, or publish. Every result explicitly says release_accepted=false.
Actual owner/reviewer decisions and their exact-candidate binding remain required. Positive unit
fixtures are invented and are never copied into actual gate or release records.

```powershell
.venv/Scripts/python.exe scripts/verify_release_evidence.py gate --record docs/evidence/G1-contracts-20261104.json
# Only after a real candidate and reviewed evidence exist:
.venv/Scripts/python.exe scripts/verify_release_evidence.py release --manifest PATH_TO_MANIFEST --artifact-root PATH_TO_REVIEWED_LOCAL_DIRECTORY --candidate-review
# Only after the exact A05 decision and stable release record exist:
.venv/Scripts/python.exe scripts/verify_release_evidence.py release --manifest PATH_TO_MANIFEST --artifact-root PATH_TO_REVIEWED_LOCAL_DIRECTORY
```

The latter two paths are intentional placeholders, not runnable claims of an existing release.
No complete release manifest exists today. Current V1.0 development package1.0.0.dev0 cannot
pass stable acceptance; public final version V1.0 still requires the exact release decision.
Gate-only exit0 means a valid observation record, including an honestly blocked record; it never
means that the recorded gate passed. Release mode exits1 for missing/invalid evidence or blockers.

The exact manifest shape is docs/evidence/templates/release-manifest.schema.json, exported from
the strict development models and guarded against drift. Unknown fields are rejected. Required
records include source commit, all three exact lock hashes, unique artifact names/hashes,
G0–G8 observations, tested OS edition/build/x64 evidence, every T01–T24 result, support matrix,
native validation, security review, packaged journeys, measured performance, AI evaluation,
pilot, handbook and signing decision. Each proof binds a plain contained file hash and source
commit plus actor/date/status. Native resource samples, reviewer findings, scenario inputs and
cleanup results live in those reviewed proof files. Do not reduce them to an unsupported pass
label. Reference-only metadata cannot replace the actual detailed acceptance review.

Pass gates require nonempty successful command evidence at the same source revision, UTC dates,
a decision identity and no blockers. Native scenarios remain blocked when their capture is
missing; a fake transport or hosted runner cannot be recorded as native/live acceptance.
Critical/high/untriaged-severity findings block release. Lower severity exceptions must be
documented and owner-approved in the security review with impact, rationale and target version.

Candidate review requires passing G0–G7 and all proof/scenario records. It permits pending or
blocked G8 while preparing the exact owner request, and rejects an explicit G8 rejection or an
unapproved owner-decision record. Stable review additionally requires release stage, a stable
non0.x/non-rc version, passing G8 and exact approved owner record. Neither mode makes the human
decision. Unsigned status is disclosed rather than silently upgraded to signed; the signing
proof must contain the actual verification or explicitly accepted unsigned policy/owner choice.
Applicable organization signing requirements cannot be waived by this helper.

Reject traversal, absolute references, streams, ambiguous Windows aliases, links/reparse paths,
missing files, wrong source revisions, modified bytes and duplicate Windows-aliased artifact
identities. Evidence payload limits are2MiB for the manifest and1MiB for each gate record.
Before making a sanitized public evidence summary, review all free text and paths for private
lab/case details. Raw captures, credentials and private orchestrator logs stay outside Git.

Prepared release.yml only invokes this checker on owner-selected reviewed source and local
paths; it has no upload or publication capability. A real local exact-candidate A05 record
must be reviewed before the owner follows manual publication instructions.
