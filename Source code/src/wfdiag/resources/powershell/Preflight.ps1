[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$result = [ordered]@{
    schema_version = '1.0'
    administrator_token = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    powershell_version = $PSVersionTable.PSVersion.ToString()
    netsecurity = 'unavailable'
    security_events = 'unknown'
    audit_visibility = 'unknown'
    audit_raw = $null
}
try {
    $systemModules = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\Modules'
    $moduleFile = Join-Path $systemModules 'NetSecurity\NetSecurity.psd1'
    Import-Module -Name $moduleFile -ErrorAction Stop
    $command = Get-Command -Name Get-NetFirewallRule -Module NetSecurity -ErrorAction Stop
    if ($command) { $result.netsecurity = 'supported' }
}
catch [System.UnauthorizedAccessException] { $result.netsecurity = 'denied' }
catch { $result.netsecurity = 'unavailable' }
try {
    $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
        'Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        '*[System[(EventID=5157 or EventID=5152)]]')
    $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    try { $result.security_events = 'supported' }
    finally { $reader.Dispose() }
}
catch [System.UnauthorizedAccessException] { $result.security_events = 'denied' }
catch [System.Security.SecurityException] { $result.security_events = 'denied' }
catch { $result.security_events = 'unavailable' }
try {
    $auditExecutable = Join-Path ([Environment]::SystemDirectory) 'auditpol.exe'
    $raw = (& $auditExecutable /get '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /r 2>$null) -join "`n"
    if ($LASTEXITCODE -eq 0) {
        $result.audit_visibility = 'supported'
        $result.audit_raw = $raw.Substring(0, [Math]::Min(4096, $raw.Length))
    }
}
catch { $result.audit_visibility = 'unknown' }
$result | ConvertTo-Json -Depth 4 -Compress
