# Dependency declarations and verified local resolution

pyproject.toml declares compatibility ranges; three reviewed Windows/Python3.13x64 hash locks
contain8 core,16 integrated and67 development packages. Actual approved/fresh installs are
verified below. Ranges do not claim every intermediate version is tested. Keep exact pins and
review metadata/advisories/licenses before changes; never invent tested pins. The initial setup
proposal below is retained as history, superseded by the actual resolution records.

| Group | Direct dependencies | Purpose |
|---|---|---|
| Core | pydantic >=2,<3; defusedxml >=0.7,<1; Jinja2 >=3.1,<4 | Strict models, XML defense, escaped static reports |
| desktop | PySide6-Essentials >=6.8,<6.13 | Qt Widgets/Core/Gui only; Windows10 retained |
| ai | httpx >=0.28,<1 | Async bounded REST transport; no provider SDKs |
| dev | setuptools >=77, wheel, pytest, pytest-cov, hypothesis, ruff, mypy, build, pip-tools, pip-audit, Windows pyinstaller | Tests, strict checks, locks, audit, build |
| desktop-test | pytest-qt | Observable widget tests |

Use standard-library argparse, hashing, IP handling, times, logging, subprocess and files. A small
native ctypes WinCred wrapper is implemented with source doubles; actual credential acceptance
is blocked. No credential dependency or plaintext fallback exists.
PySide6 and HTTPX bounds extend the master declaration for approved addenda; lower bounds are
proposals, not verified support. No PyQt, WebEngine, QML, theme/icon framework, local LLM,
LangChain, vector DB, app server, Node build or telemetry package is proposed.

Python prerequisite: official standard GIL-enabled CPython 3.13 x64 NuGet build package, resolved
to an exact reviewed available version, extracted only under .build/tools/python313. Python's
Windows documentation describes these as build environments without a system-wide installation:
https://docs.python.org/3.13/using/windows.html#the-nuget-org-packages (read 2 November 2026).
Use api.nuget.org/v3-flatcontainer/python/index.json to select the reviewed 3.13 patch, then the
exact version's python.<version>.nupkg. Record URL, publisher metadata, SHA256, native signature
observations and interpreter/venv/pip results before trusting it. Validate archive paths before
extracting. No system installer, registry/PATH change or global Python replacement is approved.
If this route cannot provide verified working venv/build support, record the failure and prepare
an A00 amendment for a concrete alternative; do not silently switch runtimes.

Create .venv and .venv-lockcheck in Product. Redirect pip download/cache files into .build/cache
and ordinary runtime temporary files as needed. PyPI and files.pythonhosted.org are proposed
package sources; exact transitive dependencies are resolver output to review. Prefer compatible
wheels; an unexpected source build or new system compiler requires review before expanding setup.
Read-only official docs/advisory/license metadata is authorized in the proposal; never send cases.
pip-audit may send package names/versions to pypi.org vulnerability APIs; no source/cases/secrets.

Proposed locks: requirements.txt (core), requirements-desktop-ai.txt (core+desktop+ai),
requirements-dev.txt (integrated development superset including desktop-test, constrained to
matching runtime pins). Generate exact hashes on recorded Windows/Python target and verify
fresh --require-hashes installs. Current developer host differs from endpoint support target:
reverify locks/build environment on the approved target before release claims. Record bootstrap
pip/setuptools/pip-tools/build/PyInstaller versions, and build with prepared --no-isolation tools.
No locks exist at A00 because no dependency has been resolved or installed. Read-only NuGet
index lookup listed standard 3.13 releases, but detailed 3.13.17 page/nuspec reads were
unavailable through the web reader; no version was accepted, downloaded or validated. Exact
package metadata and availability must be checked after A00 before any runtime execution.

Qt distribution needs a reviewed licensing choice, exact bundled module notices, applicable
source/replacement information and dependency obligations. MIT applies only to original code.
Certificates/HTTPX transitive notices and native runtime notices belong in the integrated ZIP.

## Verified initial development resolution

CPython 3.13.17 x64 was acquired from the reviewed PSF NuGet package and native python.exe/
python313.dll signatures validated. .venv and .venv-lockcheck are project-local; no system
runtime/PATH/security configuration changed. Actual direct runtime pins: Pydantic 2.14.2,
defusedxml 0.7.1, Jinja2 3.1.6, PySide6-Essentials 6.12.0/Shiboken 6.12.0/Qt 6.12.0 and HTTPX 0.28.1.
ADR0011 records the narrower Essentials choice. Core/integrated/dev locks contain8/16/67
packages, exact hashes and matching runtime pins. Hash-checked fresh core and development
installation passed. Initial candidate audit reported no known advisories; this is not a
security guarantee or the complete G4 review. Full dependency/Qt licensing and release notices
remain required. These locks were generated on development build22621.4317, not a certified
endpoint. Revalidate on the release build environment and the revised Windows10/11 targets.

Qt package guidance checked: https://doc.qt.io/qtforpython-6/package_details.html . Strict model
and lock guidance checked: https://docs.pydantic.dev/latest/concepts/strict_mode/ and
https://pip-tools.pypa.io/en/latest/ . Exact logs/hashes are in private foundation-artifacts.json.

The67th development-only candidate is Apache2.0 types-defusedxml0.7.0.20260504; metadata/advisory
review and updated hash installation passed. Owner's Windows10/11 amendment bounds desktop
below6.13 because Qt documents6.12 as its last Windows10-supporting release. All three locks
were regenerated with the reviewed candidate constraints and remain byte-identical. No pin or
package changed, so their recorded hash-install verification remains applicable. ADR0013 records
the minimum Windows10 1809+x64 baseline. https://doc.qt.io/qt-6.12/windows.html
