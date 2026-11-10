param(
    [switch]$LabOnly,
    [Parameter(Mandatory=$true)][string]$LabConfig,
    [Parameter(Mandatory=$true)][string]$ApprovalRecord,
    [Parameter(Mandatory=$true)][string]$ApprovalRecordSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$RunId
)
if (-not $LabOnly) { throw 'Explicit -LabOnly and exact A01 are required for cleanup.' }
. (Join-Path $PSScriptRoot 'Lab.Common.ps1')
$config = Confirm-Lab $LabConfig $ApprovalRecord $ApprovalRecordSha256
if ([guid]::Parse($RunId).ToString() -cne $RunId) { throw 'Canonical run UUID required.' }
$runRoot = Join-Path $config.case_root $RunId
Assert-PlainPath $runRoot
$context = Read-LabJson (Join-Path $runRoot 'context.json')
if ($context.run_id -cne $RunId -or $context.approval_sha256 -cne $ApprovalRecordSha256 -or
    $context.config_sha256 -ine (Get-FileHash -LiteralPath $LabConfig).Hash) { throw 'Different run/config/approval record.' }
$baseline = Read-LabJson (Join-Path $runRoot 'baseline.json')
$group = 'WFDiagLab-' + $RunId
$toRemove = @()
foreach ($index in @(1, 2)) {
    $planPath = Join-Path $runRoot ('planned-rule-' + $index + '.json')
    if (-not (Test-Path -LiteralPath $planPath)) { continue }
    $createdPath = Join-Path $runRoot ('created-rule-' + $index + '.json')
    if (-not (Test-Path -LiteralPath $createdPath)) { throw 'Post-create identity missing. Inspect exact planned rule/snapshot; automatic cleanup is refused.' }
    $record = Read-LabJson $createdPath
    $expectedName = $group + '-' + $index
    if ($record.name -cne $expectedName -or $record.group -cne $group -or
        $record.run_id -cne $RunId -or -not $record.instance_id -or
        @($baseline.rules | Where-Object { $_.Name -ceq $record.name }).Count -ne 0) {
        throw 'Cleanup identity is invalid or existed before this run.'
    }
    $all = @(Get-NetFirewallRule -PolicyStore PersistentStore)
    $matches = @($all | Where-Object { $_.Name -ceq $record.name })
    if ($matches.Count -eq 0) { continue }
    if ($matches.Count -ne 1 -or $matches[0].InstanceID -cne $record.instance_id -or
        $matches[0].Group -cne $group -or $matches[0].Description -cne ('WFDiagLab exact run ' + $RunId)) {
        throw 'Current rule is not the recorded exact created object. No deletion.'
    }
    $toRemove += $matches[0]
}
foreach ($createdRule in $toRemove) {
    Remove-NetFirewallRule -InputObject $createdRule -Confirm:$false
}
$after = Get-LabBaseline
$beforeProfiles = $baseline.profiles | ConvertTo-Json -Depth 8 -Compress
$afterProfiles = $after.profiles | ConvertTo-Json -Depth 8 -Compress
$beforeRules = $baseline.rules | ConvertTo-Json -Depth 8 -Compress
$afterRules = $after.rules | ConvertTo-Json -Depth 8 -Compress
$same = $beforeProfiles -ceq $afterProfiles -and $beforeRules -ceq $afterRules
$resultPath = Join-Path $runRoot ('cleanup-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.json')
Save-NewJson $resultPath @{ at_utc = [DateTime]::UtcNow.ToString('o'); baseline_metadata_equal = $same;
    status = $(if ($same) { 'metadata_restored_requires_operator_review' } else { 'blocked_baseline_difference' }); after = $after }
if (-not $same) { throw 'Baseline metadata differs. Preserve evidence and inspect; never restore/import whole policy automatically.' }
# No wildcard/group deletion, no profile disable, policy import or Security-log clearing.
