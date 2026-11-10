# Stream complete reports with separate output budgets

On5 November2026, the actual100000-finding synthetic analysis reopened successfully,
but buffered full JSON rendering produced190048115bytes, exceeding128MiB, and the
renderer child reached1091289088bytes lifetime peak working set. Full HTML expansion
also exceeds128MiB. An indexed500-row GUI view must never become the export source.

Report services continue to read and validate the complete original Analysis. They now
stream output into the existing no-overwrite atomic writer, checking cancellation and
actual cumulative bytes. Full JSON shares the compact serializer used by analysis
persistence. It explicitly includes root schema_version1.0 and metadata defaults;
optional default-valued finding/rule fields may be omitted only when the unchanged
schema reconstructs identical values. Required nulls, false eligibility, source status,
uncertainty, evidence, policy and optional log observations/rejections are preserved.
This changes representation, not diagnostic meaning or the1.0 schema.

Share HTML/JSON use the same allowlisted ShareFinding construction and one fresh
per-report pseudonym map as the buffered API. Rows are generated lazily; no raw free
text or reverse map enters the derivative. Full HTML streams per-finding dictionaries,
event JSON and optional log records through Jinja autoescaping and StrictUndefined.
HTML UTF8 chunks are at most64KiB. There is no safe-markup bypass, script, remote
resource or imported link. The buffered compatibility helper remains bounded; services
use the iterator. Cancellation or a byte refusal removes staging and retains prior files.

## Explicit format limits

JSON report output remains128MiB. HTML report output has its own256MiB cap because
escaped markup expands the same evidence. The master specifies128MiB per input source
and256MiB total case input, not an HTML output cap. Earlier code reused the analysis
record cap for HTML; this ADR makes the output change explicit. Analysis/input caps,
100000-event cap,512MiB engine target and900MiB combined-process target are unchanged.
Exceeding either output cap refuses the entire export rather than silently dropping rows.

Actual source exports retained100000 findings: full JSON131347201bytes, share JSON
29100772bytes, share HTML58381039bytes and full HTML203636834bytes. Full JSON
reconstructed the identical canonical Analysis. The128MiB HTML attempt refused and
removed staging; the256MiB attempt wrote the complete file. Incremental HTML inspection
found100000 finding headings and no active elements. Export-child peaks were about
634–639MB. These are uncontrolled development-host observations, not reference, native
privacy, browser, frozen or combined-process acceptance. All failures remain recorded.

## Validate completed worker output without retaining all rows

Large full JSON uses the existing fully validated held-file index, then closes it on the
validation worker and returns the original path. Large share JSON validates every strict
ShareFinding plus the complete header/count before returning only the path. It never
returns an empty/partial ShareReport as complete. ShareReport currently has no cross-row
invariant beyond count; any new invariant requires revisiting this incremental validator.
Generated share metadata is capped at256KiB characters and each row at64KiB characters.
The complete128MiB JSON syntax/duplicate/depth/value and held-file identity checks remain.

Small JSON keeps the ordinary inline model path under an actual held4MiB cap; only a typed
size refusal selects the large path. Shared record reading releases raw bytes before model
decoding. HTML validation streams the entire file under256MiB while retaining only a4KiB
header prefix for template/CSP checks and checking opened identity before/after. This checks
trusted generated output consistency, not arbitrary HTML safety or a browser-rendering pass.
Final opening remains deliberate and restricted to a validated generated output path.

A separate source GUI probe reduced large-share output-validation heartbeat from717.634ms
to27.4955ms by discarding validated rows instead of sending a whole report model to the
window. It does not pass the whole export journey, frozen/native or combined memory gates.
Exact command/source/lock hashes and underlying observations remain in private checkpoints.
