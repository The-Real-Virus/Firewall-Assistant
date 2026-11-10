# Windows10 and11 standard x64 desktop compatibility

Owner explicitly amended the target on2 November2026, then selected all standard x64 desktop
editions on Windows10 1809+ and Windows11, including Home/Pro/Enterprise/Education/N/LTSC.
This supersedes the original Pro25H2-only restriction; diagnostic/security scope is unchanged.

Eligibility uses workstation product type1, x64 and build17763 or newer. Edition names never
exclude Home/N/Education/LTSC. Actual collection still requires verified Windows PowerShell5.1,
NetSecurity, access and supported source fields. Missing Filter Origin or event variants remain
uncertainty rather than invented identity. Eligibility is not successful collection/certification.

Qt6.12 supports Windows10 1809+ x64 and Windows11 x64 and is documented as the last Qt version
supporting Windows10. Bound the desktop declaration below6.13 to prevent an updater silently
dropping the requested Windows10 baseline. Existing exact6.12.0 pins remain unchanged; regenerate
locks and check the resolution. No additional runtime package or system installation is needed.

Native/clean-VM checks remain blocked. Owner plans a Windows10 VirtualBox manual test after
local executable preparation; exact build/edition/results are unknown. This does not certify
every edition/build, authorize lab changes, approve a pilot or approve a release. x86, ARM,
pre1809 Windows10, Server, IoT Core and locked S-mode deployment are outside this package target.
Never change Windows security settings to make the portable application start.

Primary references reviewed2 November2026:
https://doc.qt.io/qt-6.12/windows.html
https://docs.python.org/3.13/using/windows.html
https://support.microsoft.com/en-us/windows/experience/platform-variants/windows-10-and-windows-11-in-s-mode-faq
