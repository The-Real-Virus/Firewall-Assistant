# Local evaluation installation and verification

V1.0 Release candidate, internal package1.0.0rc1, is an unsigned local candidate. Local Windows
builds and CLI/wheel checks exist; broad native/privacy/collection/clean-machine acceptance
remains blocked. No target is
release-certified. Required scope is standard x64 Windows10 1809+ and Windows11 desktop editions,
including Home/Pro/Enterprise/Education/N/LTSC. See support-matrix.md for exclusions and evidence.
Portable diagnostics require no internet, AI key or intended Python installation. Actual
clean-machine proof is still required.

Use the exact reviewed local evaluation in the current checkpoint and BUILD-RESULT.md. Older
evaluations are retained as history. No download was published. Before a future public download,
verify the owner-supplied official URL, exact SHA256 and signing statement against its approved
release record. No such project URL exists yet.

```powershell
Get-FileHash -LiteralPath 'PATH_TO_REVIEWED_ZIP' -Algorithm SHA256
```

Compare all64 digits with a separately trusted record. A checksum detects changed bytes; it does
not establish a publisher. This evaluation has no Authenticode signature. Do not disable security
software or bypass execution policy if extraction/launch is blocked.

Extract the whole ZIP to a new protected local folder. Keep FirewallAssistant.exe, wfdiag.exe,
_internal, examples, notices and build-manifest.json together. Do not run from inside the ZIP,
copy only one EXE or mix evaluations. Wheel/source archives and SHA256SUMS accompany the separate
evaluation directory. Both executables are asInvoker; no automatic elevation/runtime installer. A deliberate user
permission request may launch only the fixed read-only collector through Windows consent;
the GUI and AI remain unelevated. Cancel the Windows prompt to refuse this request.

From the extracted FirewallAssistant folder, these safe CLI operations actually ran on the
development host, including an extraction path containing spaces and Unicode:

```powershell
.\wfdiag.exe --help
.\wfdiag.exe --version
.\wfdiag.exe report --analysis .\examples\expected-analysis.json --mode share --out NEW_SHARE_REPORT.html
```

Choose a new output file in an existing local parent. The example reads invented data and never
collects host evidence. Comprehensive native privacy and clean-machine acceptance remain
open; synthetic workflows and safe share smoke do not pass those gates.

The desktop entry is FirewallAssistant.exe. Double-click it after extracting the complete folder.
The older0.1.0 evaluation has a confirmed packaging defect: an unrelated ICU DLL prevents Qt
loading. Use the replacement evaluation recorded in BUILD-RESULT.md; do not repair or mix DLLs
manually. The build now isolates native dependency resolution and checks the actual GUI.
Clean-target compatibility still requires evidence. Startup verifies private per-user storage
and an instance lock before preferences; it neither collects nor enables AI. Open example loads
the shared engine's invented result. Missing/modified/mismatched sibling engines are refused
before preparing a packaged job with complete-folder repair guidance. That check does not
authenticate a malicious manifest or independently validate every runtime DLL.

With no console attached, early Python/Qt failures show a native message with support code
GUI_IMPORT_FAILED or GUI_STARTUP_FAILED. Preserve the code; do not disable security software
or download individual DLLs. A maintainer startup check can use `--startup-check` with a new
absolute test directory. It opens/renders the GUI, loads the invented example with AI/history
off, closes and releases its lock; it does not collect host evidence. This test is run by the
local build/verification scripts and is not required of the end user.

The project-local .venv and independently hash-installed .venv-lockcheck already exist here.
Entry points are .venv/Scripts/wfdiag.exe and .venv/Scripts/firewall-assistant.exe. Actual wheel
reinstall with --no-index/--no-deps, installed-source/resource equality and an isolated core probe
passed. This developer environment test does not establish clean consumer-machine behavior.

For a new reviewed development checkout, use approved local CPython3.13x64 and exact hashes,
without global runtime/PATH/security changes. After environment setup is authorized:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes -r requirements-dev.txt
.venv/Scripts/python.exe -m pip install --no-deps --no-build-isolation -e .
```

The Windows lock is not a universal Linux lock. Qt/HTTPX are optional source extras and excluded
from core CLI imports. Follow dependencies.md and ci.md; do not resolve arbitrary release versions.
Keep Qt<6.13 for Windows10. Collection is a separate deliberate authorized operator action;
opening the GUI grants no permission. Use authorized current-user access for native reads.
Privileged collection, credential procedures and lab changes need separate authorization.
No API key is needed for installation.
