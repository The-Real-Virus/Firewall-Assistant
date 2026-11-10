# Local Windows evaluation packaging

Start with the repository's [rebuild guide](REBUILD.md). The commands below run inside the prepared build workspace.

Build only on native Windows with the tested Python3.13 x64 and exact development lock.
The spec creates separate windowed/console executables and one shared portable directory.
Both remain asInvoker. No signing, publication, install, security change or lab helper is run.

The evaluation remains unsigned with release gates unpassed. Building now verifies actual
frozen GUI startup/render/icon/example/AI-off/history-off in a new private Product test root.
It does not establish native collection, comprehensive private ACLs, accessibility or clean-machine support.
Do not distribute as a finished release. Qt licensing choice, complete native/component
notices/source and replacement instructions still need final redistribution review.

The original seven-size icon is generated locally from reviewed drawing code:

```powershell
.\.venv\Scripts\python.exe scripts/generate_app_icon.py
```

After installing the exact reviewed development lock, generate a current audit and keep
its command result/log with the report. This build does not install dependencies. Use the
actual local audit path; old private review files are not required from another checkout.

```powershell
.\.venv\Scripts\python.exe -m pip_audit -r requirements-dev.txt --disable-pip --require-hashes --strict --vulnerability-service pypi --format cyclonedx-json --output .build/dependency-review.cdx.json
.\.venv\Scripts\python.exe scripts/build_windows.py --audit-report .build/dependency-review.cdx.json
```

Every attempt uses new ignored output/work directories and preserves prior attempts.
The recorded1st attempt failed on unnecessary roaming user-site discovery; ADR0016 records
the narrow in-process isolation adjustment. No roaming directory or ACL was changed.

The multi-executable specification uses the selected PyInstaller6.22.3 API and shared
COLLECT layout. No one-file extraction, UAC-admin, UPX, lab resources or test mocks belong
in the candidate. Console source installation stays independent of Qt and AI.

ADR0021 isolates build PATH to the approved Python/Windows roots, rejects foreign native
binaries and bundling Windows ICU, and repeats actual GUI startup after Unicode-path ZIP
extraction. This fixes the original0.1.0 silent-start defect caused by ambient Poppler ICU.
The portable filename uses V1.0-RC1. Python package metadata uses 1.0.0rc1.
Full startup-check duration includes example loading/rendering/cleanup and is not a cold
ready-for-interaction budget measurement. Reference-machine performance remains unverified.

References reviewed on4 November2026:
[spec files](https://pyinstaller.org/en/stable/spec-files.html),
[Windows options](https://pyinstaller.org/en/stable/usage.html),
[Qt licensing](https://doc.qt.io/qt-6.12/licensing.html).
