# Source-only controlled lab helpers. Native Windows PowerShell5.1 execution is unvalidated.
# Never dot-source from the product. No execution-policy bypass or elevation fallback.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PrivateLiteral([string]$Value) {
    $address = $null
    if ($Value.Contains('%') -or -not [Net.IPAddress]::TryParse($Value, [ref]$address)) {
        throw 'Use exact RFC1918/ULA lab address literals, not hostnames.'
    }
    $bytes = $address.GetAddressBytes()
    $private = if ($bytes.Length -eq 4) {
        ($bytes[0] -eq 10) -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
    } else { ($bytes[0] -band 254) -eq 252 }
    if (-not $private) { throw 'Internet, loopback, multicast and unspecified targets are refused.' }
    return $address
}

function Assert-PlainPath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or
        $Path.Contains('..') -or $Path.Substring(2).Contains(':') -or
        $Path.IndexOfAny([char[]]'*?"<>|') -ge 0) { throw 'Use a plain absolute local path.' }
    foreach ($character in $Path.ToCharArray()) {
        if ([int]$character -lt 32) { throw 'Control characters are refused.' }
    }
    foreach ($part in $Path.Substring(3).Split([char[]]'\/')) {
        if ($part.EndsWith(' ') -or $part.EndsWith('.') -or
            $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') {
            throw 'Ambiguous Windows path aliases are refused.'
        }
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item -is [IO.FileInfo]) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse file refused.' }
        $item = $item.Directory
    }
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse paths are refused.'
        }
        $item = $item.Parent
    }
}

function Save-NewJson([string]$Path, $Value) {
    Assert-PlainPath ([IO.Path]::GetDirectoryName($Path))
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 12))
    if ($bytes.Length -gt 4194304) { throw 'Lab record exceeds4MiB.' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
                            [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Read-LabJson([string]$Path) {
    Assert-PlainPath $Path
    if ((Get-Item -LiteralPath $Path).Length -gt 4194304) { throw 'Oversized lab record.' }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Confirm-Lab([string]$ConfigPath, [string]$ApprovalPath, [string]$ApprovalSha256) {
    Assert-PlainPath $ConfigPath
    Assert-PlainPath $ApprovalPath
    if ($ApprovalSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-FileHash -LiteralPath $ApprovalPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ApprovalSha256) {
        throw 'Exact reviewed A01 decision hash is required.'
    }
    $config = Read-LabJson $ConfigPath
    $approval = Read-LabJson $ApprovalPath
    if ($approval.approval_id -cne 'A01' -or $approval.decision -cne 'approve' -or
        $approval.lab_config_sha256 -cne (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'A01 does not approve this exact lab configuration.'
    }
    foreach ($script in @('Lab.Common.ps1', 'Invoke-Scenario.ps1', 'Reset-Lab.ps1')) {
        $expected = $approval.script_sha256.PSObject.Properties[$script]
        if ($null -eq $expected -or $expected.Value -cne
            (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $script) -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw 'A lab script differs from its approved hash.'
        }
    }
    if ($config.schema_version -ne 1 -or $config.computer_name -cne $env:COMPUTERNAME -or
        $config.isolated_network_verified -cne $true -or -not $config.vm_name -or
        -not $config.snapshot_id -or $config.rule_prefix -cne 'WFDiagLab' -or
        $config.profile -cnotin @('Domain', 'Private', 'Public') -or
        $config.direction -cnotin @('Inbound', 'Outbound')) { throw 'Incomplete or different lab identity.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This separately approved fixture setup requires an explicit elevated lab session.'
    }
    $local = Assert-PrivateLiteral $config.local_address
    $peer = Assert-PrivateLiteral $config.peer_address
    if ($local.Equals($peer) -or $local.AddressFamily -ne $peer.AddressFamily -or
        $config.port -lt 1024 -or $config.port -gt 65535) { throw 'Invalid exact interface/peer/port.' }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $exactBuild = [string]$os.BuildNumber + '.' + [string]$version.UBR
    if ($exactBuild -cne $config.windows_build -or $version.EditionID -cne $config.edition_id -or
        -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess -or
        [int]$os.BuildNumber -lt 17763) {
        throw 'The approved Windows build/architecture does not match.'
    }
    $interfaces = @(Get-NetIPAddress -IPAddress $config.local_address)
    if ($interfaces.Count -ne 1 -or $interfaces[0].InterfaceIndex -ne $config.interface_index) {
        throw 'Configured local address is not uniquely assigned to the approved interface.'
    }
    $networks = @(Get-NetConnectionProfile -InterfaceIndex $config.interface_index)
    if ($networks.Count -ne 1) { throw 'Ambiguous network profile.' }
    $actualProfile = [string]$networks[0].NetworkCategory
    if ($actualProfile -eq 'DomainAuthenticated') { $actualProfile = 'Domain' }
    if ($actualProfile -cne $config.profile) { throw 'Configured active profile differs.' }
    Assert-PlainPath $config.fixture_exe
    if ([IO.Path]::GetExtension($config.fixture_exe) -cne '.exe' -or
        $config.fixture_sha256 -cne (Get-FileHash -LiteralPath $config.fixture_exe -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'Standalone fixture identity differs; do not use a shared Python interpreter.'
    }
    Assert-PlainPath $config.case_root
    $acl = Get-Acl -LiteralPath $config.case_root
    $allowed = @($identity.User.Value, 'S-1-5-18', 'S-1-5-32-544')
    if (-not $acl.AreAccessRulesProtected) { throw 'Precreate an approved protected private lab root.' }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin $allowed) {
            throw 'Lab output root permits an unexpected principal.'
        }
    }
    return $config
}

function Get-LabBaseline {
    return [ordered]@{
        at_utc = [DateTime]::UtcNow.ToString('o')
        profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled,
            DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules, LogBlocked)
        rules = @(Get-NetFirewallRule -PolicyStore PersistentStore | Sort-Object Name |
            Select-Object Name, InstanceID, Group, Enabled, Direction, Action, Profile, Description)
    }
}
