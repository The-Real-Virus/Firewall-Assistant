# Retention, upgrade, rollback and removal

Implemented source behavior is described below; native ACL/credentials/clean upgrade/removal
acceptance is pending. No cleanup service, telemetry, updater or startup task is installed.

| Data | Lifetime/control | Removal boundary |
|---|---|---|
| Portable program | Complete owner-selected folder, both EXEs/_internal/manifest together | Close jobs/app and separately review exact folder removal |
| Default application root | Qt GenericDataLocation plus WFDiag-FirewallAssistant | Native known-folder/private ACL acceptance pending; never guess another user's path |
| Preferences | Private preferences-v1.json,128KiB cap, theme/motion/work-root/history only | Close app before approved removal; no keys/AI-enabled state serialized |
| Recent cases | Off by default; opt-in, explicit names/paths, at most20 | Entry/Clear history/disable changes index only |
| Cases/analyses/intent/job requests | Private work root, fresh UUID outputs/per-job request.json | Persist until reviewed operator retention; clear history/logs never removes them |
| Exports | Explicit new local destination, full disclosure acknowledgement | Separate operator retention; review share derivatives before disclosure |
| Technical stderr | Current/last diagnostic job in memory, at most1MiB | Idle Clear diagnostic log buffer, new job or exit; no secure-erasure promise |
| AI question/preview/response/conversation/usage | Bounded session state, no disk conversation store | Clear conversation/Disable/close as labelled; provider retention separate |
| Session API key | Masked local entry; session-only default | Disable/close drops references; no secure-memory-erasure guarantee |
| Remembered key | Explicit provider-scoped Windows generic credential | Forget app key for selected provider; revoke at provider separately |

Exact credential targets: WFDiag/OptionalAI/openai/v1, WFDiag/OptionalAI/anthropic/v1 and
WFDiag/OptionalAI/google/v1. Never remove unrelated credentials. Native write/read/forget remains
unvalidated and needs A01/A07 as applicable. Prefer Forget app key before program removal;
deleting the program folder neither removes that credential nor revokes a provider key. If app
unavailable, use an authorized credential-management procedure for only the exact target, without
dumping secrets to files.

Seven-day raw-case retention is a proposed operator policy, not an automatic timer. Agree actual
retention with the evidence owner, preserve required originals and retain failed/incomplete
captures honestly. Review exact paths before removal. Changing work location creates a new private
folder and never migrates/deletes earlier jobs/cases/exports. Sensitive copies can exist at multiple
previous locations.

Upgrade by extracting the new reviewed ZIP side by side, after source/hash/signature/support
verification. Retain old whole folder and evidence, close jobs and run one version at a time.
Never replace only one EXE/DLL. Revalidate inputs; unsupported major formats fail, without silent
migration. No schema migration/downgrade compatibility promised. Rollback selects the previous
complete reviewed folder after closing the newer app and preserves newer data/version constraints.
No policy restore/import is involved.

Before removal, cancel/wait for owned jobs, forget saved app credentials you wish removed,
disable AI and close. Review program/data/history/export/credential items independently. Ordinary
file removal is not secure erasure and cannot remove provider-retained/other copied data. No
uninstall script deletes owner-selected folders, changes firewall policy or lowers security.
