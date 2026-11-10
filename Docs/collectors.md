# Read only Windows collectors

CLI and desktop use the same fixed Windows PowerShell5.1 resources. Collect-Host reads OS,
registry/CIM and network interfaces. Numeric IPv6 scope is removed only when it matches the
separately recorded interface index. Mismatched scopes remain invalid.

Collect-Policy reads ActiveStore profiles and authoritative TracePolicyStore rules. A full
Show-NetFirewallRule enumeration supplies seven filter classes. A local-only DCOM CIM session
reads MSFT_NetFirewallRuleFilters with explicit ActiveStore option. References join through
ordered native CIM key tuples, including class and key names/values; reference InstanceID is
not assumed populated or equal to another ID. Missing/ambiguous joins remain incomplete.
Rule names up to4096 characters are preserved exactly through findings and comparisons.

Collect-Events reads existing Security5157/5152 records using named XML fields. Lookback is
1–60minutes, default10, anchored before policy enumeration. One extra event detects100000-record truncation. No audit configuration,
firewall change, test traffic or target launch occurs. Unknown semantics remain unknown.

Every resource uses the absolute verified system PowerShell path, fixed -File arguments,
NoProfile, NonInteractive, shell=false, curated environment,120-second timeout and owned
process cleanup. SHA256-pinned script/helper handles prevent in-flight changes. Bounded512KiB
frames and ordered protocol/count validation prevent incomplete transport becoming complete.
Callers cannot supply a script, executable or remote host.

The owner approved RemoteSigned only in the collector child process. Explicit local Restricted
or AllSigned settings, or registry read failure, suppress that argument; Group Policy still
governs execution. Persistent policies, certificates, Internet markings and privileges are not
changed. Internet-marked unsigned distributions can still be refused. No bypass mode exists.

Cases retain provenance, source states and uncertainty. Unsupported conditions remain restrictions;
missing filters never become Any, and capped details become truncated. Limits are128MiB/source
and256MiB/case. Interrupted .incomplete output is rejected by the ordinary importer. A finalized
case with source gaps can still be analyzed and returns incomplete5. The GUI/AI remain normal users.
Only an explicit user permission action may launch the verified sibling wfdiag.exe with Windows
runas consent, fixed permission-collect arguments and a new protected output slot. AI cannot
invoke this path. Cancellation is cooperative and bounded; unfinished output is not a case.

## Observed host result on 8 November 2026

Windows11 x64 build22621.4317, non-admin: host1, network17, profiles3 and rules524 complete;
Security events access denied. Full capture took68.179seconds. The incomplete case analyzes
with exit5 and exports a share report with exit0. No raw evidence was uploaded. Exact private
command logs/fingerprints are in .build. Data-only PowerShell5.1 parsing of five resources passes.

A later real user-consented frozen GUI collection read that protected event source successfully:
host1/network17/profiles3/rules524 complete, events empty, normal analysis NO_RELEVANT_EVENT.
The GUI stayed non-admin. Read-only AuditQuerySystemPolicy observed both system failure audit
flags disabled; per-user audit policy may differ. No firewall/audit/policy setting changed.
This is current-host observation, not isolated ground truth, cross-account privacy, historical
continuity or all-edition certification. Unavailable validation remains blocked.
Source/synthetic tests supplement native evidence.

Microsoft references: [ActiveStore and filters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule),
[EnumerateFull](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/enumeratefull-msft-netfirewallrule),
[Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
and [execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1).
