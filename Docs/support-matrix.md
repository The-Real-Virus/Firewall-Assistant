# Support and environment matrix

Owner-confirmed target: all standard x64 desktop editions on Windows10 1809+ and Windows11.
Fixture/component checks exist; no native collection/build row is release-certified.

| Environment | Role | Status and evidence |
|---|---|---|
| Windows10 1809+ x64 Home/Pro/Enterprise/Education, N/LTSC variants | Required target | Capability selection fixture-tested; native and clean-VM validation blocked |
| Windows11 x64 Home/Pro/Enterprise/Education, N/LTSC variants | Required target | Capability selection fixture-tested; native and clean-VM validation blocked |
| Owner's Oracle VirtualBox Windows10 Pro22H2 x64 build19045.6466 VM | Manual evaluation endpoint | Replacement GUI launch and10 CLI fixture outcomes observed; preflight architecture unknown and actual collection source failures; AI success unresolved. No disposable isolated lab approval |
| Current host AMD64 build22621.4317, DisplayVersion22H2, Professional | Approved read-only development host | RC1 GUI/CLI startup and host1/network17/profiles3/rules524 capture verified; Security events denied, case incomplete; not isolated ground truth or all-target certification |
| Current host registry ProductName Windows 10 Pro | Raw registry label | Conflicts with platform Windows-11 label; preserve raw facts and use build evidence |
| Windows10 pre1809, x86/ARM, Server, IoT Core, locked S-mode deployment | Outside confirmed package target | No support claim; no security-setting workaround |
| Managed policy on target desktop editions | Conservative evidence behavior | GPO/MDM/local-merge restrictions route to policy owner; no managed-deployment certification |
| Linux/other systems | Portable fixture analysis and tests | Not Windows collection/package validation |

Observed PowerShell host: 7.6.5; native Windows PowerShell 5.1.22621.4249 exists and command
discovery finds Get-NetFirewallRule in NetSecurity. Command availability is not successful
collection or evidence access. Security channel access, audit settings and actual policy were
not probed. Owner VM is Test Win10 on VirtualBox7.2.20. Saved evidence has no snapshot and a
bridged adapter; this is not an authorized isolated privileged lab. No such lab is available here.

Git 2.50.1.windows.1 is available. py --list-paths reports no installed Pythons. Bundled document
runtime is CPython3.12.14 AMD64 for documents only. Approved project-local CPython3.13.17 x64
and PySide6-Essentials/Shiboken/Qt6.12.0 are installed and locked; no system runtime changed.
Qt6.12 supports Windows10 1809+ x64/Windows11 x64 and is documented as its last Windows10
release; the declaration is bounded below6.13. Upstream support is not application validation.
Reference: https://doc.qt.io/qt-6.12/windows.html . See ADR0013 for the owner amendment.

Supported behavior remains TCP desktop Win32 IPv4/IPv6 subject to real tests. UDP, shared host
processes, dynamic RPC, AppContainer, IPsec, VPN/third-party filters retain explicit limitations.
Adapters use OpenAI Responses, Anthropic Messages and Gemini generateContent.
Google3.5 Flash-Lite has actual synthetic source and frozen chat/application-action evidence;
OpenAI/Claude live operation remains unverified. Google3.8 has one connection success and timeouts.
Development live tests used invented examples only. No key or internet is required for diagnostics.
