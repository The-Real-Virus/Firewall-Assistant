[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'Collection.Common.ps1')
function Get-PolicyIdentity($Object) {
    # Association references populate CIM keys, not the non-key InstanceID.
    # Use the exact same ordered native key tuple on both ends of the join.
    $keys = @($Object.CimInstanceProperties | Where-Object { ($_.Flags -band [Microsoft.Management.Infrastructure.CimFlags]::Key) -ne 0 } | Sort-Object Name)
    if ($keys.Count -eq 0) { throw [IO.InvalidDataException]::new('Missing native identity') }
    $parts = @($Object.CimClass.CimClassName)
    foreach ($key in $keys) { $parts += $key.Name; $parts += [string]$key.Value }
    ConvertTo-Json -InputObject $parts -Compress
}
$moduleReady = $false
$moduleState = 'unsupported'
try { Import-SystemModule 'NetSecurity'; $moduleReady = $true }
catch { if ((Get-FailureState $_) -eq 'access_denied') { $moduleState = 'access_denied' } }
foreach ($source in @('profiles', 'rules')) {
    Start-Source $source
    $count = 0
    $state = 'complete'
    $codes = @()
    if (-not $moduleReady) {
        Finish-Source $source $moduleState 0 @('NETSECURITY_UNAVAILABLE')
        continue
    }
    try {
        if ($source -eq 'profiles') {
            Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                if ($count -ge 3) { throw [IO.InvalidDataException]::new('Profile count cap') }
                Write-Frame @{ kind='record'; source='profiles'; data=(Get-NativeFields $_) }
                $count++
            }
        }
        else {
            $classes = @{
                application='MSFT_NetApplicationFilter'; address='MSFT_NetAddressFilter'
                port='MSFT_NetProtocolPortFilter'; service='MSFT_NetServiceFilter'
                interface='MSFT_NetInterfaceFilter'; interface_type='MSFT_NetInterfaceTypeFilter'
                security='MSFT_NetNetworkLayerSecurityFilter'
            }
            # Enumerate full ActiveStore once. Join only through native association
            # references; filter IDs are never assumed equal to rule IDs.
            $graph = @{}
            $nodes = 0
            Show-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                $nodes++
                if ($nodes -gt 80000) { throw [IO.InvalidDataException]::new('Policy graph cap') }
                $className = $_.CimClass.CimClassName
                if ($className -in $classes.Values) {
                    $key = Get-PolicyIdentity $_
                    if ($graph.ContainsKey($key)) { throw [IO.InvalidDataException]::new('Duplicate filter identity') }
                    $graph[$key] = Get-NativeFields $_
                }
            }
            $links = @{}
            # Explicit local DCOM avoids the default transport's BadEnumeration
            # response for this provider. Never connect to a remote computer.
            $session = [Microsoft.Management.Infrastructure.CimSession]::Create('localhost', [Microsoft.Management.Infrastructure.Options.DComSessionOptions]::new())
            $options = [Microsoft.Management.Infrastructure.Options.CimOperationOptions]::new()
            try {
                $options.SetCustomOption('PolicyStore', 'ActiveStore', $false)
                $linkCount = 0
                foreach ($link in $session.EnumerateInstances('root/standardcimv2', 'MSFT_NetFirewallRuleFilters', $options)) {
                    $linkCount++
                    if ($linkCount -gt 70000) { throw [IO.InvalidDataException]::new('Association cap') }
                    if ($link.GroupComponent.CimClass.CimClassName -ne 'MSFT_NetFirewallRule') { continue }
                    $ruleId = Get-PolicyIdentity $link.GroupComponent
                    $filterKey = @{ class=$link.PartComponent.CimClass.CimClassName; identity=(Get-PolicyIdentity $link.PartComponent) }
                    if (-not $links.ContainsKey($ruleId)) { $links[$ruleId] = @() }
                    $links[$ruleId] += $filterKey
                }
            }
            finally { $options.Dispose(); $session.Dispose() }
            Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop | ForEach-Object {
                if ($count -ge 10000) { throw [IO.InvalidDataException]::new('Rule count cap') }
                $rule = $_
                $ruleTime = Get-UtcStamp
                $filters = @{}
                $errors = @()
                foreach ($group in $classes.Keys) {
                    $references = @($links[(Get-PolicyIdentity $rule)] | Where-Object { $null -ne $_ -and $_.class -eq $classes[$group] })
                    if ($references.Count -eq 1 -and $graph.ContainsKey($references[0].identity)) { $filters[$group] = $graph[$references[0].identity] }
                    else { $filters[$group] = $null; $errors += ($group.ToUpperInvariant() + '_FILTER_ASSOCIATION_INCOMPLETE') }
                }
                Write-Frame @{ kind='record'; source='rules'; at_utc=$ruleTime; data=@{ rule=(Get-NativeFields $rule); filters=$filters; filter_errors=@($errors) } }
                $count++
                if ($errors.Count) {
                    if ($errors -match '_ACCESS_DENIED') { $state = 'access_denied' }
                    elseif ($state -ne 'access_denied') { $state = 'error' }
                    $codes = @('ASSOCIATED_FILTER_INCOMPLETE')
                }
            }
        }
    }
    catch { $state = Get-FailureState $_; $codes = @('POLICY_ENUMERATION_INCOMPLETE') }
    if ($state -eq 'complete' -and $count -eq 0) { $state = 'empty' }
    Finish-Source $source $state $count $codes
}
