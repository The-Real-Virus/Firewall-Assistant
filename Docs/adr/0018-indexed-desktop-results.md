# Keep fully validated large desktop results on a held file

On5 November2026, the same invented100000-finding result exposed two source GUI
problems. Qt ResizeToContents sampled the whole loaded500-row Evidence page during
repaints. Bounding width measurement to16 rows preserved every loaded record and
reduced measured interaction p95 from584ms to60–63ms. This changes sizing work only;
selection, search, sort, local reveal and exported evidence retain their previous scope.

Full Analysis loading on a background Qt thread still retained approximately542MB
and caused275–278ms event-loop intervals during model construction. Moving work off
the event thread alone did not prevent Python runtime pauses. Do not raise budgets,
reduce the fixture, disable garbage collection or relax validation to hide this.

For GUI result files above4MiB, AnalysisIndex now owns a held plain, singly linked
file and its opened directory. It retains validated metadata, UTF8 byte-offset pairs
and an initial500-finding page. It validates the entire file before exposing a case:
the existing128MiB/32-depth/10000000-value syntax and duplicate-property guard,
every unchanged strict Finding model,100002-finding cap, distinct global finding IDs,
and unchanged Analysis metadata/source/completeness/context rules. An eligible witness
exercises the Analysis rules that forbid any eligible finding without complete evidence
and confirmed intent. These rules are existential; count/uniqueness validate independently.
Changes to Analysis invariants require reviewing the indexed path and parity tests.

Offsets are UTF8 bytes, including any BOM, rather than character positions. Unicode,
escaped structural characters and root property order have round-trip coverage. The
opened identity/size/times must remain unchanged during indexing and each page read;
an incomplete marker always refuses the result. Windows read sharing prevents writes
or deletion while held. Other platforms retain the existing before/after identity checks,
not an authentication or hostile same-user guarantee. A page read revalidates its records.

The index is an internal view resource, never a full engine Analysis or export. Its
metadata deliberately has no findings. The view explicitly holds the current page and
separate total count. Page I/O runs on the existing one-job background controller; the
old page remains visible until the validated replacement arrives. Widget/model binding
stays on the event thread. Cancelled unbound results, rejected versions, stale worker
results, replacement and final close release held handles. No file mutation is introduced.

Full report/proposal/comparison services continue to read the original complete file
through the shared engine. They never export the GUI's partial view. AI context remains
selected-finding allowlisted, but its local disclosure policy traverses **every indexed
page** on the AI review worker. Off-page identities remain forbidden; existing privacy
budgets fail closed rather than truncating their index. No new AI authority or network
permission results. Disabled AI still imports or starts no assistant implementation.

Small results keep the ordinary full Analysis path. No dependency, serialized schema,
diagnostic classification, proposal rule, source evidence or approved visual direction
changes. Actual source measurements and retained failures are in gui/performance.md.
Native/private/frozen/reference VM performance and accessibility remain blocked.

The small-path decision uses a4MiB caller budget on the actually held file and actual bytes,
before decoding. Only a typed byte-budget refusal falls back to full indexed validation.
There is no pathname-size check followed by a separately opened uncapped full-model read;
a replacement cannot force a large result onto the small path. CLI/full services retain
their original128MiB cap. An actual worker test exports all1001 original findings while the
indexed GUI displays only its one-record last page, preventing accidental partial exports.

Profiling isolated repeated small file reads as the dominant remaining page cost. Normal
pages read one contiguous span of at most4MiB; exact UTF8 offsets still select each finding
for unchanged strict validation. A larger span, including hostile whitespace, falls back
to individual reads rather than allocating an oversized page buffer. No rows are dropped.
Evidence display caches only revealed text for the current500 rows and clears on hide;
hidden fields are not formatted or searched. Repeated unchanged reveal states do not
invalidate the whole proxy. These are bounded I/O/display repairs, not diagnostic changes.
