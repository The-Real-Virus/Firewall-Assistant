# CLI contract

Shared doctor/analyze/report/propose/compare services and the local desktop-job worker are
implemented. Collect now connects fixed host/policy/event resources to bounded private case
assembly. Windows private output and native collection acceptance remain blocked.

```powershell
wfdiag doctor --out doctor.json
wfdiag collect --minutes 10 --out case-001
wfdiag analyze --bundle case-001 --intent intent.json --out analysis-001
wfdiag report --analysis analysis-001 --mode share --out report-share.html
wfdiag propose --analysis analysis-001 --finding-id F001 --intent intent.json --out proposal-F001.json
wfdiag compare --before analysis-001 --after analysis-002 --out comparison.json
```

Analyze accepts no intent for general findings; propose always requires validated intent and an
actual eligible finding ID. Existing outputs are never overwritten. Analyze creates a new private
directory containing analysis.json; interrupted execution retains an .incomplete marker that blocks
both directory and direct-file imports. A fully written evidence-incomplete result is readable
and returns5. Imported eligibility is replayed from structured facts, with exactly the same intent.
Report accepts .html or .json output; share mode uses an allowlisted derivative. Full/proposal/
comparison outputs require an already verified private parent directory. Comparison records
actual captured rule/profile changes and cannot establish repair. Native privacy tests are blocked;
service round trips used an explicitly labelled storage double rather than claiming ACL acceptance.
Codes: 0 operation completed (not host secure), 2 invalid input, 3 unsupported capability/platform,
4 required access denied, 5 incomplete collection/analysis, 6 internal failure. Findings alone do
not fail a complete analysis. Keep stdout/stderr separate and errors actionable and bounded.

Collect reads only within current access; it never requests elevation or changes policy/auditing.
The1–60-minute option selects existing evidence, default10. Required-source failures preserve
a finalized evidence-incomplete case and return5; inability to create a private output is4, and
an out-of-target host is3 without source execution. Interrupted folders retain .incomplete and
are rejected by ordinary import. See collectors.md for limits and blocked native validation.

Internal desktop-job --request ABSOLUTE_REQUEST_JSON requires a fresh private canonical UUID
job directory and a bounded typed request. Its versioned NDJSON, cancellation/EOF, deadline and
exit/output agreement are exercised through actual processes. Its contract is a bounded local adapter, not a general
command-execution API. No apply/fix/allow-all/disable/upload commands. Ordinary CLI never imports
Qt or AI adapters. Source commands use the explicit .venv console executable after P01 exists;
the portable CLI is the sibling wfdiag.exe.

Exercised source share export (choose a new output name if it exists):

```powershell
.\.venv\Scripts\wfdiag.exe report --analysis examples\expected-analysis.json --mode share --out report-share.html
```

No API key, provider, internet or PowerShell collection is needed for this synthetic offline export.

Reports export the complete original analysis, including when the GUI displays a500-finding
page. Choose `.html` or `.json` and a fresh destination. JSON output is capped at128MiB;
HTML output at256MiB to allow escaped markup expansion. Input-source/analysis128MiB and
total-case256MiB limits are unchanged. Writes stream with cancellation and actual-byte
checks; a failure removes staging instead of publishing a truncated report. Compact full
JSON reconstructs the same schema1.0 values, including optional logs and required unknowns.
Full mode remains sensitive and requires a verified private parent. See ADR0020.
