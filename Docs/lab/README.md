# Controlled native laboratory preparation

Source helpers exist; native syntax and behavior have not run. No A01 has been approved.
The owner's intended Oracle VirtualBox Windows10 VM is recorded, but its exact guest name,
edition/build, checkpoint, interface and isolated peer are unknown. Do not run these on the
development host. Current PowerShell5.1 script-policy refusal remains blocked; do not retry or
bypass it. Review an approved signing/development procedure before any future native execution.

## Exact A01 packet to complete

Copy lab-config.template.json into the private lab record and fill actual facts only. Supply
the named disposable VM/computer, exact Windows build including UBR and EditionID, checkpoint,
host-only/internal network isolation, configured interface index, local/peer RFC1918 or ULA
literals, one profile/direction/port, exact standalone fixture path/hash and a precreated protected
private case root. Confirm the peer belongs to this lab; a private IP alone does not prove that.
Use separate exact configurations for different interfaces/directions/families/scenarios.

Record the reviewed commit, helper/config/fixture hashes and exact elevated setup/read/capture/
cleanup commands, expected data, retention and snapshot recovery. Review existing auditing and
permission state; this packet does not authorize changing auditing, profile/default actions,
network categories, managed policy or production endpoints. If those are required, prepare the
specific additional commands first and obtain a scoped amendment. Never disable a firewall profile.

After the owner actually approves that concrete packet, record A01 and its UTC decision, packet
digest, exact config digest and every helper digest in the private decision record. Its digest is
then an explicit command argument. Templates with pending/null facts are intentionally unusable.
These checks prevent accidental wrong-run execution; a JSON file is not cryptographic proof of
human approval. Independently verify all reviewed scripts before launching or dot-sourcing them.
Line-ending/signing changes require new exact hashes and review.

## Helper behavior and current limits

Invoke-Scenario.ps1 requires LabOnly, the exact approved decision/config/scripts, matching guest
build/interface/profile, private peer, standalone executable hash, an explicitly elevated session
and a protected lab output root. It creates a fresh canonical UUID run directory and saves profile/
local-rule metadata baseline before any mutation. T01/T05/T06 require an existing enabled default
Block; defaults are never changed. T02 creates an exact scoped block and conflicting allow;
T03 creates a disabled block; T04 creates a scoped allow on one approved different profile;
T07 creates two scoped block candidates. All names/groups start WFDiagLab plus the unique run UUID,
with exact program, local/peer addresses, TCP service port, direction and profile. It never starts
the fixture, captures traffic or declares a diagnostic result. Other cases get an explicit blocked
setup record and require their reviewed manual/fixture instructions in the scenario catalog.

Reset-Lab.ps1 validates the same context and every proposed deletion before deleting anything.
It removes only exact post-create InstanceID/name/group/description objects recorded by that run,
which must not have existed in its baseline. No wildcard/group removal, policy import, audit change
or log clearing exists. Missing post-create identity after interruption refuses automatic cleanup:
inspect the exact prejournaled object and recover through the approved snapshot/manual procedure.
After cleanup, baseline metadata must compare equal or the helper exits failed. Metadata equality
is narrower than full filter/policy/no-mutation acceptance; retain full independently reviewed
native captures for G2/G4. Same-user/administrator filesystem races and policy changes remain risks.
The scripts are not product resources and are excluded from the portable application.

Standalone tcp_fixture.py uses standard library only. The build helper creates a separate unsigned
asInvoker console folder under ignored .build, never in the product portable folder. Copy its whole
folder into the approved lab and record the Windows-observed application identity; do not substitute
a shared Python interpreter. It binds only the configured concrete interface, restricts its exact
peer, sends fixed text, receives a bounded fixed-length response, has a1–60s total deadline and no
DNS, shell, payload execution, firewall writes or arbitrary file access. IPv6 uses ULA and V6ONLY.
Private literals and LabOnly are safety checks, not permission to generate network traffic here.

## Proposed commands, not executed native instructions

Replace ALL_CAPS tokens from the real approved record. Use a new UUID and output path for each
scenario. Run only after script policy/signing is resolved normally and the exact A01 is approved:

```powershell
powershell.exe -NoProfile -File .\scripts\lab\Invoke-Scenario.ps1 -Scenario T01 -LabOnly -LabConfig CONFIG_PATH -ApprovalRecord A01_PATH -ApprovalRecordSha256 DECISION_HASH -RunId RUN_UUID
# On the approved guest and peer separately; exact opposing listen/connect args belong in A01:
WFDiagLabFixture.exe --lab-only --bind-address LOCAL_IP --peer-address PEER_IP --port SERVICE_PORT --mode listen --lifetime 15 --run-id RUN_UUID
# Use explicit CLI/GUI preflight/collection in a fresh private case; preserve all result codes.
powershell.exe -NoProfile -File .\scripts\lab\Reset-Lab.ps1 -LabOnly -LabConfig CONFIG_PATH -ApprovalRecord A01_PATH -ApprovalRecordSha256 DECISION_HASH -RunId RUN_UUID
```

The reverse peer runs connect with its own bind IP and the guest peer IP; connect binds local
port0 so T05 cannot mistake an ephemeral client port for the remote service port. A blocked flow
can make this fixture exit2; that is reproduction evidence, not the diagnostic verdict. Preserve
setup/flow/capture/findings/eligibility/cleanup separately. Follow docs/test-plan.md T01–T24 and
scenarios.json; all actual native outcomes are currently blocked. Never inject synthetic events
and call them native evidence. Fill actual captures, expected ground truth, timestamps, source/
artifact hashes, completeness, results and cleanup; retain failed/skipped observations.

Reviewed cmdlet reference only; selected Windows10/11 native behavior remains unverified:
[New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule),
[Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule),
[Remove-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/remove-netfirewallrule).
Reading these references and reviewing source do not pass PowerShell syntax or lab execution.
