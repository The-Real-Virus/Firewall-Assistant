# Rebuild Firewall Assistant V1.0 from source

These steps produce the unsigned x64 Windows package from the repository's source. The application shows V1.0. The internal package version and portable ZIP use the release candidate identifier. Start with a fresh directory for each rebuild to keep outputs easy to identify.

## 1. Prepare Windows, Python, and Git

Use a native x64 Windows desktop, x64 Python 3.13.17, Git on PATH, and PowerShell. Internet access is needed to acquire the pinned Python dependencies and run their advisory audit. The built diagnostic engine runs offline. The Python distribution must include its runtime license text in the Python installation directory so the packager can include the required runtime notice.

Open the repository folder in VS Code, then open a PowerShell terminal at the repository root. Confirm Python and Git are available.

```powershell
py -3.13 -c "import struct, sys; print(sys.version); print(8 * struct.calcsize('P'))"
git --version
```

Expect Python 3.13.17 and `64`.

## 2. Create the build workspace

Run this command from the repository root. It copies source and docs into the layout expected by the build tools and records the inputs in a local Git commit in the build workspace. The preparation tool accepts a new destination outside the repository.

```powershell
$buildRoot = Join-Path $env:TEMP ('FirewallAssistant-build-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
py -3.13 '.\Source code\prepare_build.py' $buildRoot
if ($LASTEXITCODE -ne 0) { throw 'Build workspace preparation failed' }
Set-Location -LiteralPath $buildRoot
```

## 3. Install the pinned environments

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
py -3.13 -m venv .venv-lockcheck
.\.venv-lockcheck\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
```

Stop if a command fails. The second environment verifies the generated wheel independently. The repository keeps the three lock files in `Docs`. The preparation step places copies in the build workspace.

## 4. Check and run the source

```powershell
.\.venv\Scripts\python.exe scripts/check_repository.py --suite quality
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\firewall-assistant.exe
```

Try **Open example** in the desktop app, then close it before packaging. The CLI is available at `.venv\Scripts\wfdiag.exe`. The source test suite uses synthetic fixtures and bounded local test paths.

## 5. Build and verify the portable ZIP

```powershell
.\.venv\Scripts\python.exe scripts/check_repository.py --suite package-smoke
```

This command audits the dependency lock, builds the wheel and source distribution, freezes both Windows executables, creates the ZIP, verifies its contents, and exercises safe CLI and desktop startup checks. An audit or verification failure stops the process. Read the command output and `.build\package-*\logs` in the build workspace for details.

On success, open the new `release-local\evaluation-...` directory. It contains the portable `FirewallAssistant` folder, the Windows ZIP, `build-manifest.json`, `SHA256SUMS`, and the Python build artifacts.

```powershell
$candidate = Get-ChildItem -LiteralPath '.\release-local' -Directory -Filter 'evaluation-*' |
    Sort-Object Name -Descending | Select-Object -First 1
$zip = Join-Path $candidate.FullName 'FirewallAssistant-V1.0-RC1-windows-x64.zip'
Get-FileHash -Algorithm SHA256 -LiteralPath $zip
Get-Content -LiteralPath (Join-Path $candidate.FullName 'SHA256SUMS')
```

Extract the ZIP into a new folder and launch `FirewallAssistant.exe`. Confirm the application shows V1.0 and opens the sample case. The build records identify the build workspace snapshot and input hashes. A separate rebuild creates its own archive and checksum because packaging records and ZIP timestamps vary.

Before distributing a binary, review the bundled dependency notices and the Qt corresponding source and library replacement requirements. [Packaging details](packaging.md) · [Qt redistribution requirements](https://www.qt.io/development/open-source-lgpl-obligations)
