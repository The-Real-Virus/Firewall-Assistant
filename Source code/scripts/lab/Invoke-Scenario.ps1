param(
    [Parameter(Mandatory=$true)][ValidatePattern('^T(0[1-9]|1[0-9]|2[0-4])$')][string]$Scenario,
    [switch]$LabOnly,
    [Parameter(Mandatory=$true)][string]$LabConfig,
    [Parameter(Mandatory=$true)][string]$ApprovalRecord,
    [Parameter(Mandatory=$true)][string]$ApprovalRecordSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$RunId
)
if (-not $LabOnly) { throw 'Explicit -LabOnly is mandatory. No lab execution is approved by default.' }
. (Join-Path $PSScriptRoot 'Lab.Common.ps1')
$config = Confirm-Lab $LabConfig $ApprovalRecord $ApprovalRecordSha256
if ([guid]::Parse($RunId).ToString() -cne $RunId) { throw 'Canonical run UUID required.' }
$runRoot = Join-Path $config.case_root $RunId
if (Test-Path -LiteralPath $runRoot) { throw 'Use a new run directory; preserve earlier evidence.' }
[IO.Directory]::CreateDirectory($runRoot) | Out-Null
$baseline = Get-LabBaseline
Save-NewJson (Join-Path $runRoot 'baseline.json') $baseline
Save-NewJson (Join-Path $runRoot 'context.json') ([ordered]@{
    scenario = $Scenario; run_id = $RunId; config_sha256 = (Get-FileHash -LiteralPath $LabConfig).Hash
    approval_sha256 = $ApprovalRecordSha256; fixture_exe = $config.fixture_exe
    fixture_sha256 = $config.fixture_sha256; windows_build = $config.windows_build
    actual_result = 'not_run'; cleanup_status = 'pending'
})
if ($Scenario -cnotin @('T01', 'T02', 'T03', 'T04', 'T05', 'T06', 'T07')) {
    Save-NewJson (Join-Path $runRoot 'blocked.json') @{ status = 'blocked'; reason = 'Use the separately reviewed scenario instructions; no automated setup exists for this case.' }
    throw 'Scenario requires separate fixture/manual ground truth; no setup or success was invented.'
}
if ($Scenario -eq 'T06' -and (Assert-PrivateLiteral $config.local_address).AddressFamily -ne
    [Net.Sockets.AddressFamily]::InterNetworkV6) { throw 'T06 requires an approved ULA IPv6 interface/peer.' }
if ($Scenario -eq 'T05' -and $config.direction -cne 'Outbound') { throw 'T05 is outbound client scope.' }
if ($Scenario -eq 'T01' -and $config.direction -cne 'Inbound') { throw 'T01 is inbound default-block scope.' }
$profile = @($baseline.profiles | Where-Object { $_.Name -ceq $config.profile })
if ($profile.Count -ne 1 -or [string]$profile[0].Enabled -ne 'True') {
    throw 'The active lab firewall profile must stay enabled.'
}
if ($Scenario -cin @('T01', 'T05', 'T06')) {
    $default = if ($config.direction -ceq 'Inbound') { $profile[0].DefaultInboundAction } else { $profile[0].DefaultOutboundAction }
    if ([string]$default -cne 'Block') { throw 'Existing approved default is not Block. This helper never changes a default action.' }
    Save-NewJson (Join-Path $runRoot 'setup.json') @{ status = 'ready_for_manual_reproduction'; created_rules = @(); verdict = 'not_tested' }
    return
}
$count = if ($Scenario -cin @('T02', 'T07')) { 2 } else { 1 }
$group = 'WFDiagLab-' + $RunId
for ($index = 1; $index -le $count; $index++) {
    $name = $group + '-' + $index
    if (@($baseline.rules | Where-Object { $_.Name -ceq $name }).Count -ne 0) { throw 'A planned rule name already existed.' }
    $ruleProfile = $config.profile
    if ($Scenario -ceq 'T04') {
        $ruleProfile = $config.alternate_profile
        if ($ruleProfile -cnotin @('Domain', 'Private', 'Public') -or $ruleProfile -ceq $config.profile) { throw 'Approve one different rule profile for T04.' }
    }
    $action = if (($Scenario -ceq 'T02' -and $index -eq 2) -or $Scenario -ceq 'T04') { 'Allow' } else { 'Block' }
    $enabled = if ($Scenario -ceq 'T03') { 'False' } else { 'True' }
    $parameters = @{
        PolicyStore = 'PersistentStore'; Name = $name; DisplayName = $name; Group = $group
        Description = ('WFDiagLab exact run ' + $RunId); Program = $config.fixture_exe
        Direction = $config.direction; Action = $action; Enabled = $enabled; Profile = $ruleProfile
        Protocol = 'TCP'; LocalAddress = $config.local_address; RemoteAddress = $config.peer_address
    }
    if ($config.direction -ceq 'Inbound') { $parameters.LocalPort = [string]$config.port }
    else { $parameters.RemotePort = [string]$config.port }
    # Prejournal the exact planned identity before mutation. An interrupted post-create record
    # requires human inspection/snapshot recovery, never guessed or broad deletion.
    Save-NewJson (Join-Path $runRoot ('planned-rule-' + $index + '.json')) $parameters
    $created = @(New-NetFirewallRule @parameters)
    if ($created.Count -ne 1 -or $created[0].Name -cne $name -or $created[0].Group -cne $group) {
        throw 'Unexpected creation result; stop and inspect this exact run before cleanup.'
    }
    Save-NewJson (Join-Path $runRoot ('created-rule-' + $index + '.json')) @{
        name = $name; instance_id = [string]$created[0].InstanceID; group = $group; run_id = $RunId
    }
}
Save-NewJson (Join-Path $runRoot 'setup.json') @{ status = 'ready_for_manual_reproduction'; verdict = 'not_tested'; created_rule_count = $count }
# No target/fixture launch, capture, policy import, profile/audit change or successful verdict here.
