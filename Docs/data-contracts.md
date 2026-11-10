# Data contracts

Implemented core/report/collector/desktop/AI contracts and22 exported schemas. Native and full
frozen workflow acceptance remain pending. Engine schema_version
1.0 is distinct from desktop protocol_version 1 and the separate AI schemas. Reject unknown
major versions, extra fields where strict contracts require it, invalid enums, unbounded values
and unsafe paths. Preserve absent, unavailable, unsupported, unknown and real empty separately.

Case directory: manifest.json, host.json, profiles.json, rules.json, events.ndjson,
collection-errors.json; optional declared network.json/firewall-log.txt. No raw EVTX or arbitrary
archives. Manifest records run/collector/schema versions, UTC collection and snapshot windows,
per-source status, host/build metadata, relative filenames, actual sizes and SHA256. Hashes
establish consistency, not sender authentication. File/byte/reparse validators operate on opened
inputs. Default limits: 1–60 minute lookback (10 default), 100000 events, 128 MiB/source,
256 MiB/case, 120 s/collector operation. Streaming limits include actual bytes.

Normalized event: event_id, provider, record_id, event_version, timestamp_utc, application_raw,
application_canonical if resolved, pid_raw/pid_value if valid, direction, source/destination
addresses and ports, protocol, filter_runtime_id, filter_origin, interface_index and source_ref.
Never turn runtime filter IDs into persistent rule IDs, current PID matches into historical
identity, localized messages into schema, or guessed native paths into drive-letter certainty.

Rules preserve stable Name/InstanceID, enabled/action/direction/profile/provenance and associated
application, port, address, service, interface, interface type and security filters; missing or
unsupported filters make candidate matching incomplete. Evaluate every relevant condition.

Finding: finding_id, category, evidence_grade, summary, observation, evidence_refs, candidate_rules,
policy_snapshot_utc, relevance, limitations, alternatives, next_steps and proposal_eligible.
Categories: EXPLICIT_BLOCK, DEFAULT_BLOCK, PROFILE_MISMATCH, LOCAL_RULE_MERGE_RESTRICTED,
UNRESOLVED_WFP_BLOCK, EVIDENCE_GAP, NO_RELEVANT_EVENT. Grades: confirmed, supported, unknown.
Source/overall completeness remains independent of finding count and grade.

Intent preserves the master example: schema_version, application_path,
application_identity_confirmed, direction, protocol, profile, remote_addresses, local_port,
remote_port, purpose. One verified Win32 identity, TCP, one profile, approved peer and stable
service port are needed. Inbound uses local service port; outbound remote service port with
transient local port unset. Confirmation is an operator attestation, not machine proof.
Proposal requires relevant supported default block, complete necessary evidence, no conflicting
explicit block or unknown managed/security/interface condition; contains Allow, exact scope,
evidence, assumptions, review steps, change description and executable false. No apply script.

Desktop requests: protocol_version, job_id, operation (doctor/collect/analyze/report/propose/compare),
typed parameters, absolute input/output paths, expected engine version. Private fresh job
directory, atomic request. UTF8 NDJSON events carry version, job_id, increasing sequence and type
started/progress/warning/completed/failed/cancelled. 16 KiB/line, 2 MiB aggregate, private stderr
1 MiB with truncation marker. Bounded matching cancel stdin; EOF cancels; process ownership,
bounded deadlines and staging cleanup must be verified. Late/malformed messages cannot succeed.

AI context is built, not blocklist-trimmed: random session aliases, engine category/grade/
completeness/relevance/refusal codes, TCP direction/family/necessary service port, identity
pseudonyms, approved limitation/next-step codes, reviewed question. One finding, five observations,
16 KiB context; question 1000 characters before/after redaction. Whole request <=64 KiB;
generation <=1024 documented output tokens; decoded response <=256 KiB before JSON parsing.
No raw cases, XML, paths, exact IP/CIDR, names, rule text, source errors, secrets or reverse maps.
Consent binds exact bytes, destination, model, prompt, context and schema revisions.

AI response: schema_version 1.0, status answered/insufficient_context/refused, explanation <=4000
characters, finding_refs/evidence_refs/next_step_ids <=5 known IDs each, limitations <=5 of <=300
characters. Reject extras, malformed/truncated output, unsafe directives, secrets or unknown IDs.
No trusted partial prose, model tools or engine field writes. Full local validation supplements
the provider's supported schema subset. Model compliance is not evidence of factual correctness.

## Source XML normalization limits

Internal event XML input is limited to64KiB, depth16,512 nodes,64 named data fields and4096
characters per raw field. DTDs/entities/external references and duplicate fields are rejected.
Normalized events preserve named unknowns and raw UTC fractional precision. ProcessID and
ProcessId are known source variants; simultaneous aliases are rejected. Integer syntax is
decimal or explicitly prefixed hexadecimal for PID, never inferred from a display message.
Direction token interpretation is supplied only from a verified catalog; the development
default is empty. Pure fixture tests inject a labelled test map; no native token claim follows.
File-based source collection remains blocked pending native lab evidence and approved script
execution. Normalized events.ndjson is the final case contract; intermediate XML is not an
arbitrary accepted archive or an instruction.

## Opened bundles and optional text observations

The reader holds the directory and every declared source through hashing and consumption.
Windows children use relative directory handles, reparse/single-link/final-path checks and read
sharing only. Portable development uses descriptor-relative no-follow opens and identity checks.
Source counts, actual byte budgets, duplicate JSON properties, bounded depth, finite numbers
and host/manifest consistency are checked. Manifest bytes count toward the256MiB case budget.
Consumers must finish event iteration and check unchanged sources before committing a result.

Optional text observations have firewall-log:line references, recorded wall time, optional UTC,
endpoints/ports and retained Fields-header data. Unknown local timezone stays unknown. A recorded
fixed offset or explicit UTC header enables conversion. Text path/PID never establishes identity.
Rejected lines retain references and fixed reason codes; oversize/unterminated input is truncated.
The pure parser and CLI/engine integration exist; native text captures remain pending.

## Replayable decision context

Manifest optionally records policy_snapshot_utc and policy_change_observed. Null stays unknown;
collectors cannot turn absence of change evidence into false. ADR0012 explains the120-second
freshness ceiling and continuity refusal. Profiles preserve policy_source/type, with unknown
defaults for older inputs. Unknown/managed profile ownership withholds local proposals.

Analysis optionally carries host, collection/policy times, change observation, profiles,
policy_rules and network. Event findings retain normalized event and bounded event_refs. These
private facts support detail views, policy comparison and eligibility replay. Older analyses
without decision facts can be read but cannot enable proposals. Source/profile/rule IDs and
interface indexes must be distinct.100000 event findings plus two case-level findings are bounded.
No released-consumer or cross-version compatibility is claimed by the schema1.0 default fields.

Full JSON reports share compact incremental persistence, explicitly include root1.0 metadata,
and reconstruct identical Analysis values. JSON report output is128MiB; HTML output is a
separate256MiB expansion budget. Input-source/analysis128MiB, case256MiB and resource targets
are unchanged. Share reports stream the single allowlist and fresh per-report alias map.
Large share worker output validates every row/header/count without retaining a partial model;
all complete-file syntax/identity guards remain. Review incremental validators when adding
cross-record invariants. See ADR0020 for exact output and generated-validator limits.

Persisted analysis is bounded to128MiB. Compact JSON may omit default-valued optional fields
only when the existing model reconstructs the identical value; required nulls/false decisions,
provenance and uncertainty remain. Findings/rules serialize incrementally and cancellation or
actual-byte overflow prevents finalization. The reader retains held-file identity checks, full
syntax/duplicate/numeric/string/depth checks and final Analysis cross-record invariants while
loading findings individually. Its lexical limit counts strings including keys, containers and
primitives once; separators do not count. The10-million-token and32-depth record caps are unchanged.

Share-report schema contains known source states, codes/grades/relevance, fresh aliases,
allowlisted refusals and next-step enums. Unknown refusal text becomes ADDITIONAL_RESTRICTION.
Raw context and reverse maps are omitted. Host windows_product_type distinguishes workstation1
from server2/3, separately from descriptive edition names and unverified supported_build status.

## Native resource stream

The separate private collector protocol_version1 is exported as native-collector-frame-v1.
Started/record/finished frames preserve source order, UTC observation times, count agreement,
source state and bounded codes. Raw native properties are string arrays or null; unexpected
enum values remain unknown. All seven associated filters are represented, including failures.
Unknown matching conditions retain bounded markers instead of disappearing into Any. Frames
are capped512KiB with16 levels/20000 values; final events retain the existing256KiB line budget.
The case/engine schema1.0 and desktop protocol1 do not change. Native validation remains blocked.
