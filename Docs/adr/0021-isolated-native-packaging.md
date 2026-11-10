# ADR0021 — Isolate native packaging and execute the frozen GUI

Accepted7 November2026 within the owner's approved local startup repair.

The original evaluation's real windowed executable exits3 before creating a window.
The import handler suppressed the cause. An instrumented copy reports QtCore DLL load
failure (“specified procedure could not be found”). PyInstaller's recorded Analysis
resolved `icuuc.dll` from an unrelated Poppler installation on the ambient PATH. That
library exports suffixed ICU78 functions; Qt uses unsuffixed Windows ICU entry points.
Archive-import emulation did not reproduce the actual bootloader's DLL search environment
and missed it; it must not substitute for execution of the real frozen launcher.
Excluding this foreign DLL in a preserved package copy permits actual frozen startup,
native Windows platform rendering, private-root verification, locking and clean exit0.
Original packages and owner evidence remain unchanged.

Build subprocess PATH now contains only the approved interpreter/venv and Windows paths.
Analysis rejects native binaries from other roots and rejects bundling Windows ICU.
No dependency pin, system DLL, ACL, execution policy or security setting is changed.
The desktop remains asInvoker; it never elevates automatically.

Every fresh build and extracted Unicode-path artifact verification runs the actual
`FirewallAssistant.exe --startup-check NEW_ABSOLUTE_DIRECTORY`. This creates a new
ordinary-user private test root, starts the real QApplication/native plugin, renders
the window/icon, loads the bundled synthetic example through its background path,
confirms AI/history off, closes and releases its lock. Existing directories are refused.
It never collects system evidence, opens credentials, calls a provider or navigates URLs.
Command/result logs are retained under `.build`; no test files enter the portable ZIP.

Early Python/Qt import failures now use a fixed support code and a Qt-independent native
message when no error stream exists. Exception text, paths and case/key data are not
echoed. The outer launcher catches unexpected Python exceptions with another fixed code.
Native loader failures before Python or native aborts still require OS-level evidence.

This establishes actual packaged startup on the tested development host only. It does
not replace Windows10 VM retesting, supported-build/edition coverage, native privacy/
collection tests, accessibility/performance, live AI, pilot, signing or release gates.

Owner public version sequence is V1.0, V2.0, V3.0. This unreleased build displays
`V1.0 (Development)` with PEP440 metadata `1.0.0.dev0` and numeric PE version1.0.0.0.
Portable ZIP names use `V1.0-Development`; Python wheel/source names use internal metadata.
Final V1.0 requires the recorded release gates and owner's exact release decision.
