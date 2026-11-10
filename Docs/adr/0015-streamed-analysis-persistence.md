# Stream analysis persistence and release deduplication state

On 4 November 2026, three fresh Windows development-host processes analyzed the same
100000 distinct synthetic events. The original service serialization produced209148115
bytes, exceeding the existing128MiB analysis-record cap. Absolute OS lifetime peak working
set was1013194752–1013522432 bytes, exceeding512MiB. All100000 findings were retained;
these failures cannot be repaired by reducing the fixture or raising the limits silently.

The engine now consumes completed deduplication groups incrementally. It still reads all
events before yielding any group, so late duplicate provenance is preserved. Groups keep
first-observed order; distinct record identities remain distinct. Releasing each group as
its finding is built avoids simultaneous full collections of wrappers and findings. A
provenance set is allocated only when a group actually needs multiple distinct references.

Persist analysis as compact UTF8 JSON through the existing atomic new-output mechanism.
Serialize findings and rules one at a time; enforce actual cumulative bytes and cancellation
before finalization. Default-valued optional fields may be omitted only where the existing
schema reconstructs exactly the same value. Required nulls, false decisions, source status,
uncertainty and evidence remain. Shorter engine explanations retain the same caveats;
categories, evidence grades, relevance, identifiers and proposal decisions do not change.
JSON whitespace is not a diagnostic contract. The parsed analysis and schemas stay1.0.

Streaming alone reduced output to131346965 bytes but still peaked at607174656–607313920
bytes. Inspection isolated per-event Pydantic field-tracking sets: on the locked runtime,
22 names occupied2264 bytes, while an independent copy with identical contents occupied1240.
Event post-initialization now replaces only that metadata with its own copy. No mutable
metadata is shared. Frozen values, strict validation, field membership, exclude-unset
serialization and model-copy behavior have regression coverage. This runtime-specific saving
must be remeasured after Python/Pydantic changes; it is not a permanent size guarantee.

Three final fresh processes measured42.93–43.26 seconds and503238656–503390208 bytes absolute
peak working set, retaining100000 findings each. All outputs had the same SHA256 and stayed
within128MiB. This meets development-host targets for this exact fixture; G6 is still blocked.

Reopening that actual output exposed a separate lexical-budget bug: commas were counted
in addition to their string values, while primitives were counted inconsistently. The guard
now counts each string (including keys), container and primitive once, with separators
excluded. The unchanged10000000-token,32-depth and128MiB record caps still apply. Tests
cover exact limits, primitives, escaped punctuation, duplicates, invalid numbers and depth.

The syntax/duplicate check can discard completed objects when the caller does not need
their values. Analysis loading decodes findings individually and then applies the complete
unchanged Analysis validator, retaining required source, duplicate-ID, completeness and
eligibility checks. This avoids a second complete temporary tree alongside all models.
The actual100000-finding output reopened with631578624 bytes peak, versus909238272 before
incremental loading; these observations are separate from the engine target and do not
pass the combined GUI+worker budget. Root property order and escaped text are supported.

This is an allocation/output repair, not a reference-VM pass. Local round trips and negative
atomic/cancellation tests must pass. Repeat full100000-event measurements, record every
sample and retain the failed baseline. Native/private output acceptance remains separate.

Measurement uses Windows K32GetProcessMemoryInfo and PROCESS_MEMORY_COUNTERS, including
interpreter/import overhead. It is not a Python allocation estimate or peak-minus-baseline.
The safety harness limits are180 seconds and2GiB, explicitly distinct from60s/512MiB targets.
Development-host RAM/CPU facts and exact hashes are in private measurements. No native
collector, firewall/audit query, credential operation, AI request or lab change is involved.

Official metric definitions reviewed on4 November2026:
[GetProcessMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)
and [PROCESS_MEMORY_COUNTERS](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters).
