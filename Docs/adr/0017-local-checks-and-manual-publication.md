# ADR0017 — Enforce evidence consistency and prepare source-only CI

Date:4 November2026. Status: implemented source; local checks recorded separately; remote
execution and release acceptance blocked.

P14 requires actual required-suite, schema, dependency, wheel and Windows-package checks with
immutable verified Actions and a separate privileged-lab trust boundary. The owner explicitly
keeps code/artifacts local and will publish manually. Therefore prepare local commands and
workflow files, with no remote operations, upload actions, signing or publication. release.yml
validates evidence only; this owner instruction supersedes the blueprint's artifact-attachment
step. No remote Actions workflow is described as operational before its actual execution.

Use the existing approved Windows3.13x64 lock/runtime and Pydantic development verifier; add no
dependency. Reject absent/undersized suites, empty/mismatched/vulnerable audit inventories,
unknown evidence fields and failed/stale/missing acceptance. A metadata check cannot authenticate
human testimony and always returns release_accepted=false. Actual scoped owner approvals and
G0–G8 remain the authority. The preexisting final evaluation is preserved by immutable hash and
source revision; later development-helper/docs commits do not rewrite its manifest.
