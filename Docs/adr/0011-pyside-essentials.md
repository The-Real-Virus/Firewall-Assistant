# Minimal PySide6 distribution

Status: scoped dependency refinement during approved A00 implementation.

The 2 November 2026 dry-run selected PySide6 6.12.0 and its Addons, PDF and WebEngine
distributions. The GUI specification requires only Qt Core, Gui and Widgets and excludes a
browser runtime. Use the official PySide6-Essentials distribution instead of the convenience
meta-package. Source imports remain PySide6; Shiboken is still resolved and recorded. This
narrows the approved Qt dependency surface without changing the interface or diagnostic scope.
Verify widget tests, resource tools, licenses, packaging and clean-machine behavior for the
actual resolution; metadata alone is not acceptance.
