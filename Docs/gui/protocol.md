# Desktop job protocol

The Qt-free contracts, real desktop-job adapter and asynchronous QProcess bridge are implemented.
Source real-process/fixture checks pass; native privacy/collection and frozen GUI acceptance
remain blocked. The six-operation
protocol, byte caps, job/version/sequence binding, cancellation and atomic result contract are
specified in docs/data-contracts.md. AI uses its own service and never extends this operation enum.
Resolve worker from trusted installation root and sanitize Python/Qt import/plugin overrides.
Use QProcess argument lists, allowlisted environment, fixed cwd; no shell/startCommand. Drain
stdout/stderr boundedly. Verify cancellation reaps only owned descendants; stdin EOF requests
cleanup. A process crash, malformed frame, overflow, mismatched version/job/sequence or late
completion cannot enter a successful state. Tests include actual pipe and QProcess round trips
with explicit privacy/native-source doubles where applicable. They do not establish lab ACL,
Security event access, actual collector semantics or clean-machine acceptance.

Source invocation uses the verified virtual-environment console Python with `-I -m wfdiag`.
Frozen invocation uses the absolute sibling wfdiag.exe. Only the six fixed operations exist;
AI has a separate service/worker and never extends the desktop operation enum. Request files
are bounded64KiB in fresh private UUID directories. Control stdout is16KiB per line and2MiB
aggregate; private retained stderr is1MiB with a truncation marker. Job/version/sequence,
terminal frame, process status and schema-validated output must agree before completion.

Core operation deadlines are doctor135s, collect400s, analyze/report/compare90s and propose30s,
separate from collector120s reads. Deadline/EOF requests cancellation and bounded cleanup;
a wedged worker exits incomplete. The GUI acknowledges cancellation without pretending the
underlying read has already stopped. Closing waits; no hidden tray/collection worker persists.
