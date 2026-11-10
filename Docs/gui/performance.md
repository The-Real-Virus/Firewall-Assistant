# Development performance measurements

On4 November2026 the source engine was measured on native Windows11 build22621 with
CPython3.13.17 x64,8 logical CPUs and34233393152 bytes physical RAM. This development host
is not the approved4-vCPU/8GiB reference VM. No G6, native collector, GUI responsiveness,
accessibility or clean-machine acceptance follows from these results.

The benchmark generates100000 distinct normalized events, with distinct record IDs,
timestamps and source references, from the bundled invented case. Its events source is
61277790 bytes with SHA256
`c4eb9b559400c0c576e4244a218dc14576231be3a84c1e26c1958ed90791d7f7`.
Each fresh child verifies manifest/hash/small sources, streams event validation into the
actual engine, checks all100000 findings, and serializes the result. The final method uses
the same serializer and atomic writer as the service, including flush. It uses fixed
synthetic intent, no policy rules and captured synthetic network context. It is not a
worst-case10000-rule or maximum-length-field benchmark.

| Revision of implementation | Sample | Measured stages seconds | Absolute peak working set bytes | Output bytes | Development result |
|---|---:|---:|---:|---:|---|
| Original service | 1 | 46.292 | 1013522432 | 209148115 | Memory and output fail |
| Original service | 2 | 45.998 | 1013460992 | 209148115 | Memory and output fail |
| Original service | 3 | 42.791 | 1013194752 | 209148115 | Memory and output fail |
| Streamed JSON and equivalent concise text | 1 | 42.912 | 607260672 | 131346965 | Memory fail |
| Streamed JSON and equivalent concise text | 2 | 43.225 | 607174656 | 131346965 | Memory fail |
| Streamed JSON and equivalent concise text | 3 | 42.946 | 607313920 | 131346965 | Memory fail |
| Also compact independent event metadata | 1 | 43.169 | 503390208 | 131346965 | Meets local targets |
| Also compact independent event metadata | 2 | 43.260 | 503312384 | 131346965 | Meets local targets |
| Also compact independent event metadata | 3 | 42.930 | 503238656 | 131346965 | Meets local targets |
| Final reader and token-guard revision | 1 | 42.688 | 503934976 | 131346965 | Meets local targets |
| Final reader and token-guard revision | 2 | 45.237 | 503267328 | 131346965 | Meets local targets |
| Final reader and token-guard revision | 3 | 42.561 | 503488512 | 131346965 | Meets local targets |

Time is the sum of measured input-validation, analysis and serialization stages; Python
startup is separately recorded as child wall time. Original serialization measured the
service's former full JSON/string/UTF8 allocation and rejected the over-cap output; it did
not write that invalid result. Later measurements include the actual synthetic file write.
The generator runs outside the measured child. Each final output SHA256 is
`c5a82325a8e17c85de325a780d9225fa0acb5404ebcd2d05722c70cd575776d3`.

Working set is Windows lifetime PeakWorkingSetSize including interpreter/import overhead,
not Python allocated bytes or baseline-subtracted memory. The target remains60s/512MiB
engine,128MiB result, and900MiB GUI+worker. Harness safety stops180s/2GiB are distinct from
acceptance targets. Failures remain in private logs; no threshold or input-count reduction.
Source/lock hashes, commands, platforms, sample PIDs, actual byte sizes and individual phase
times remain in ignored local measurement records. See ADR0015 for the repair rationale.

Run a separately labelled small smoke, then the full benchmark:

```powershell
.\.venv\Scripts\python.exe scripts/benchmark_analysis.py --events 100 --samples 1
.\.venv\Scripts\python.exe scripts/benchmark_analysis.py --events 100000 --samples 3
```

Still blocked: approved reference-VM repetitions; full GUI+worker peak;10 cold starts,
100 interactions, load stalls, cancellation feedback,60s idle CPU/working set,20 open/close
cycles, scaling, Narrator, high contrast and frozen/clean-machine measurements. Reopening
large saved results and report expansion need separate measurements. No release performance
or minimum-hardware promise is made.

The generated100000-finding output was also reopened through the actual held-file reader.
The first attempt correctly remained failed when a lexical separator double-count exceeded
the JSON guard. After correcting token counting, whole-model loading took27.250s and
peaked909238272 bytes. Incremental loading then took29.959s and peaked631578624 bytes,
retaining every finding. These are separate single-sample observations, not the GUI+worker
combined measurement or a claim of512MiB result-loading acceptance. The final full analysis
validator still rejects unknown schemas/fields, missing findings, duplicate IDs and complete
results with failed required sources. Later repeat samples and code fingerprints remain
required before using these numbers for release claims.

## Source desktop result-loading repair —5 November2026

The same saved131346965-byte analysis above was opened in a direct MainWindow using
the offscreen Qt plugin and Dark theme on the same development host. This exercises
real result validation, binding and painting, but bypasses app.main and native private
startup. No engine process, collector, credentials, AI or network request runs. The
fixture SHA is checked before measurement, so cache state is warm/uncontrolled.

Each run records100 interactions cycling page, tab, reveal, resize and selection,
forcing a Qt grab repaint. A10ms heartbeat records actual event-loop intervals. Width
sampling repair bounds only ResizeToContents sizing to16 records; all500 page records
remain available. The indexed path additionally includes completion of asynchronous
page reads before timing the repaint; it does not time just the request dispatch.

| Source implementation / observation | Load seconds | Interaction p95 ms | Longest heartbeat ms | Lifetime peak working set bytes | Loaded working set bytes |
|---|---:|---:|---:|---:|---:|
| Original component |30.732|583.634|1152.505|680878080|542470144|
| Bounded header sampling, repeat1 |31.160|62.503|277.835|679747584|541409280|
| Bounded header sampling, repeat2 |30.023|60.072|275.488|680501248|542228480|
| Held-file index, private probe |30.386|92.954|101.365|346775552|103153664|
| Held-file index, reproducible harness |29.440|95.707|133.091|347107328|102363136|

The remaining header-only stalls were traced to full model loading, before page binding.
ADR0018 records the indexed validation/lifetime/privacy design. All100000 findings remain
accessible; malformed off-page data and global eligibility failures refuse the whole case.
Do not sum independent engine and GUI peaks to claim the combined-process budget passed.
These observations meet selected component targets only; reference and packaged G6 remain
blocked. Both successful observations and original failures are retained, not a single best run.

Reproduce the source component against the existing exact invented benchmark output:

```powershell
.\.venv\Scripts\python.exe scripts/run_check.py gui-component .venv/Scripts/python.exe scripts/benchmark_gui.py --analysis .build/benchmark-20261104T122915066323Z-100k/sample-1/synthetic-analysis.json
```

The harness accepts only that exact recorded fixture SHA and100000 findings, checks actual
page completion, uses an owned child with an output cap/deadline and records underlying
latencies/heartbeats, OS process working-set counters and source development-host facts.
Optional `--idle-seconds 60` measures actual wall and own CPU deltas without the probe's
10ms timer; both one-core and logical-processor-normalized CPU percentages are retained.
Optional `--cycles 20` repeats open/replace in one source window, not20 process/OS launches.
Reports stay in ignored local .build; run_check retains exact command and source fingerprints.
First reusable-harness attempt incorrectly passed a relative path to the strict input reader,
never loaded a case, and expired at its watchdog. It remains a failed check. The corrected
harness makes the input absolute and fails promptly on a controller load error.

The next bounded run at clean63cbec6 completed20 open/replace cycles plus an actual60.0177s
idle period. All100000 findings remained available. One set of100 interactions measured
p95 98.3611ms; maximum heartbeat across the whole workload131.6328ms. Load times across
all20 cycles ranged29.4319–37.7367s. Working set immediately after binding increased from
101232640 to115195904bytes (13963264bytes/13.3164MiB), below the unchanged50MiB retained
growth target. All cycle samples are retained; the pattern includes small falls and gradual
growth. Lifetime peak378433536bytes includes the probe's retained heartbeat samples and
transient whole-file validation buffers; no allocator trimming/forced collection was used.

With the10ms probe heartbeat stopped, actual60.0177s idle recorded0.0 process CPU seconds
at the OS counter's resolution and115163136bytes working set. Both one-core and logical-
processor-normalized averages were0.0%; this is a measured interval, not guaranteed zero
CPU use. Background host activity/cache state were uncontrolled; these are conservative
source component observations, not a controlled reference test. There was no engine worker.
Twenty replacements in one window are narrower than repeated complete application launches.

The original failures, private first indexed sample, reproducible single sample and complete
20-cycle/idle record remain available locally with command/source/lock hashes and all raw
latencies/heartbeats. No native or release gate changes. Still required: native reference/
frozen/private-startup, actual combined-worker, cancellation/crash/slow-storage,10 cold-start
and accessibility observations. Actual packaged/OS open-close acceptance remains blocked.

### Follow-up failures, profiling and bounded batch reads

After the held-size routing correction, another complete source sample missed targets:
p95 114.2578ms and longest heartbeat217.6121ms, with346796032bytes lifetime peak and
103022592bytes loaded working set. This remains a failed budget observation. Host activity
was uncontrolled; it is not valid to discard this run in favor of the earlier20-cycle result.

Avoided constructing hidden Evidence strings and repeating unchanged reveal invalidations.
Revealed strings cache only the loaded500 rows and clear on hide; privacy/search/sort checks
still pass. A bounded profiled repeat then measured p95 97.5701ms and heartbeat107.9872ms.
The profile isolated page reads at median62.9487ms/max79.0808ms, while binding was median
2.1452ms (first binding21.3543ms). Repeated small seek/read operations dominated page work.

Normal pages now read a single contiguous span capped at4MiB, then strictly validate each
finding slice. Oversized inter-record whitespace falls back to individual reads, avoiding
a large batch buffer. UTF8/BOM/order, all-page parity, whole-file/global validation and
held identity/link/incomplete checks are unchanged. Tests observe one bounded read for a
normal500-record page and refusal to batch a whitespace-inflated span.

| Fresh source batch-read sample | Load seconds | Interaction p95 ms | Longest heartbeat ms | Lifetime peak working set bytes | Loaded working set bytes |
|---|---:|---:|---:|---:|---:|
|1|30.7360|77.7770|89.7457|346566656|105005056|
|2|29.9036|74.1779|78.6827|347443200|104267776|

Both retain100000 findings and include asynchronous completion/repaint in page timing.
All prior failures/underlying samples remain. Source sharing/export repairs are documented
in ADR0019 and independently tested. Final repeated/idle observations after these last
changes and all native/reference/frozen/combined-worker gates remain pending or blocked.
The source-only probe now records atomic status.json checkpoints so interruption cannot
be confused with a completed result; only the completed result records full observations.

## Streaming complete report observations —5 November2026

Using the same100000-finding saved input, the original buffered full JSON renderer produced
190048115bytes and reached1091289088bytes lifetime peak working set. The old parent memory
watchdog watched the venv launcher, so its memory safety stop is not claimed effective.
Later probes use actual renderer-child self-memory checks plus bounded owned process jobs.

| Source export | Actual output bytes | Renderer lifetime peak working set bytes | Outcome |
|---|---:|---:|---|
| Full JSON |131347201|634990592| Complete; canonical Analysis roundtrip matches |
| Share JSON |29100772|634789888| Complete;100000 validated rows; known synthetic identities absent |
| Share HTML |58381039|634290176| Complete;100000 headings; no active elements observed |
| Full HTML, earlier128MiB cap |203636834 generated|634556416| Refused atomic output; staging removed |
| Full HTML, explicit256MiB output cap |203636834 written|634490880| Complete;100000 headings; no active elements observed |

ADR0020 documents separate JSON128MiB/HTML256MiB output limits, streaming and preservation
of every record. Input limits and engine/combined memory targets did not change. HTML source
inspection is narrower than blocked browser layout/network QA. Raw failures are retained.
These probes run on uncontrolled development hardware; some independent probes overlapped,
so their times are not controlled throughput results. Independent peaks cannot be summed
to claim combined-process acceptance. Private/native/frozen/reference export gates remain blocked.

The separate100k share JSON output-validation Qt probe initially observed717.634ms maximum
heartbeat and326737920bytes peak. Discarding fully validated rows reduced the next observation
to27.4955ms and136519680bytes peak. Both runs and every heartbeat remain in private records.
On explicit resume, the existing203636834-byte full HTML was actually validated on the source
background loader in0.601s (including a500ms observation tail); maximum heartbeat10.922ms,
peak75644928bytes. It retained the generated path rather than a complete report object. This
does not measure generation, browser display, the whole worker journey or combined memory.

Current full source suite888 passed before the additional output/worker regressions. Those
15 affected checks pass, including all four real report formats/modes from an indexed last
page, malformed/over-budget HTML and release of large JSON validation handles. Directory
privacy is explicitly doubled in worker tests. Final current collection/quality receipts
and repeated/idle source observations are recorded at the next checkpoint, not inferred here.

### Current repeated load and real worker export

At clean2ef90fd the20 open/replace plus60.0065s idle observation completed in749.235s.
All100000 findings remained. Load times were28.3618–44.9096s; loaded working set grew
99938304→117465088bytes (17526784bytes,16.715MiB). Lifetime peak381124608bytes includes
probe sample retention. Idle working set117432320bytes and CPU delta0.0s at OS resolution;
this is an observation, not a zero-CPU guarantee. These are20 replacements in one source
window, not20 native application launches. Interaction p95 was99.8561ms, but the longest
heartbeat was205.0309ms during resize: **the200ms target was missed**. All samples remain.
Do not relabel this completed run as a complete performance pass. Resize profiling follows.

A separate exact-case source MainWindow/QProcess/real worker full HTML export completed:
203636834bytes,100000 finding headings and SHA256
`78f2192177e42f764d01f3ed2cf45b9164e85c09dccaef84aa4cc7d08e489ff2`, matching the prior
complete full HTML. Initial indexed load30.309s; worker export and output validation44.392s
including500ms observation tail. Maximum heartbeat117.775ms. Concurrent current working-set
samples peaked736546816bytes across the GUI, QProcess launcher and exact worker PID.
The10ms Qt observer deduplicates PIDs and queries retained owned-process handles; it does
not sum independent lifetime peaks. Missed transient peaks remain possible. Probe retention
is included in the GUI memory. Both owned worker/launcher exits were checked before success.

The separate cancellation run reached the actual rendering stage after full input validation.
Cancel requested and a repaint completed in41.830ms; stopped status/owned exits/no final
output/no staging were verified. Recorded cancellation-to-final observation0.846s includes
the500ms tail. Maximum heartbeat144.775ms; sampled simultaneous peak739323904bytes.
Cancellation does not imply that the preceding bounded input read was interrupted early.

Both runs use explicit directory-privacy doubles, source/offscreen window construction and
the real shared service. They perform no app.main/native private storage, collection,
credential, AI or network operation. No frozen/reference/native or G6 acceptance is passed.
Raw probes, helper hashes, logs and complete memory/heartbeat samples are retained privately.

The unprofiled single follow-up completed100 interactions: load28.257s, p9581.8954ms,
maximum heartbeat77.2923ms, peak346587136bytes and loaded99065856bytes. Profiling had
observed resize calls at most40.612ms and grabs64.631ms, without reproducing the205ms gap.
Instrumentation overhead p95166.054ms is not acceptance. The later faster source sample
does not erase the20-cycle missed interval or prove its cause resolved. No speculative
runtime change or target relaxation was made; controlled native/reference validation remains.
