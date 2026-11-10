# Allow intended sibling outputs while retaining held-input protection

On5 November2026, an actual synthetic GUI-to-worker regression tried to export a full
1001-finding share report while the indexed GUI displayed its one-record last page. It
failed with Access denied. A separate plain-file reproduction narrowed the failure to
atomic new-output creation beside an open index: WinError32, sharing violation. Reading
the held input again succeeded. The initial reproduction also used an incorrect CLI
argument; that invocation failure is retained separately from the real filesystem failure.

WindowsDirectory previously always shared only read access on its directory handle.
Long-lived indexed input views must coexist with deliberate new sibling outputs, and
verified private output directories must permit the app's atomic output mechanism.
These contexts now request read/write **sharing on the directory**, retaining read-only
desired access and refusing delete sharing. This grants no new filesystem permission,
modifies no existing ACL and does not authorize existing-file replacement. Default input
directory behavior remains read-only sharing. File handles opened relative to either
directory still share only read access, reject reparses/multiple links and hold identity.

AnalysisIndex opts into directory child-write sharing. It checks the held file's identity,
actual link count and incomplete marker on page reads. Input-file writes remain refused
on Windows; another platform detects changed input before reading a page. A new link is
either refused by Windows or causes subsequent index reads to fail. New output files
use the unchanged no-overwrite atomic writer. Parent rename/deletion remains unshared.

WindowsPrivacy's new/verified output directory handles and creation parent use the same
child-write sharing. Owner/protected-DACL/ACE/principal checks are unchanged. That source
change addresses the same output-handle conflict; actual native private startup, ACL
creation/verification, collector writes and standard/elevated acceptance remain **blocked
on A01**. No such native private operation was exercised on the development host here.

The corrected actual plain-file reproduction reads the original input and atomically
creates a new sibling while it is held. Real CLI share exports succeed both beside the
input and in another folder. GUI-to-worker regression exports all1001 findings while only
one is displayed. Tests preserve original input hash, refuse held-input writes on Windows,
and reject new hard-link changes. Private directory tests continue to use explicit doubles;
this is local source/plain-file evidence, not a native privacy gate pass.

Primary references reviewed5 November2026:
[CreateFileW access/sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [CreateHardLinkW per-file sharing/identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw).
