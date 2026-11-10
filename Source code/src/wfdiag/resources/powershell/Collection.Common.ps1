# Fixed local helper. No caller-supplied script, command, remote target or output path.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$script:FrameBytes = @{}
function Get-UtcStamp { [DateTimeOffset]::UtcNow.ToString('o') }
function Write-Frame([hashtable] $Frame) {
    $Frame.protocol_version = 1
    if ($Frame.kind -eq 'record' -and -not $Frame.ContainsKey('at_utc')) { $Frame.at_utc = Get-UtcStamp }
    $line = ConvertTo-Json -InputObject $Frame -Depth 16 -Compress
    $bytes = [Text.Encoding]::UTF8.GetByteCount($line) + 1
    if ($bytes -gt 524288) { throw [IO.InvalidDataException]::new('Collector frame byte cap') }
    if ($Frame.kind -eq 'record') {
        if (-not $script:FrameBytes.ContainsKey($Frame.source)) { $script:FrameBytes[$Frame.source] = 0L }
        if (($script:FrameBytes[$Frame.source] + $bytes) -gt (134217728 - 16384)) {
            throw [IO.InvalidDataException]::new('Collector source byte cap')
        }
        $script:FrameBytes[$Frame.source] += $bytes
    }
    [Console]::WriteLine($line)
}
function Start-Source([string] $Source, $WindowStart = $null, $WindowEnd = $null) {
    Write-Frame @{ kind='started'; source=$Source; at_utc=(Get-UtcStamp); window_start_utc=$WindowStart; window_end_utc=$WindowEnd }
}
function Finish-Source([string] $Source, [string] $State, [int] $Count, [string[]] $Codes = @()) {
    Write-Frame @{ kind='finished'; source=$Source; at_utc=(Get-UtcStamp); state=$State; count=$Count; codes=@($Codes) }
}
function Get-FailureState($Record) {
    if ($Record.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::PermissionDenied -or
        $Record.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::SecurityError) { return 'access_denied' }
    $exception = $Record.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    if ($exception -is [UnauthorizedAccessException] -or $exception -is [Security.SecurityException]) { return 'access_denied' }
    $nativeCode = $exception.PSObject.Properties['NativeErrorCode']
    if ($nativeCode -and [string]$nativeCode.Value -eq 'AccessDenied') { return 'access_denied' }
    if ($exception -is [IO.InvalidDataException]) { return 'truncated' }
    return 'error'
}
function Import-SystemModule([string] $Name) {
    # Names are literals in these resources. Never search a user/module override directory.
    $module = Join-Path ([Environment]::SystemDirectory) ('WindowsPowerShell\v1.0\Modules\' + $Name + '\' + $Name + '.psd1')
    Import-Module -Name $module -ErrorAction Stop
}
function Get-NativeFields($Object) {
    $fields = @{}
    $aliases = @{
        Profiles='Profile'; AppPath='Program'; ServiceName='Service'; InterfaceID='InterfaceAlias'
        LocalUserAuthorizedList='LocalUser'; RemoteUserAuthorizedList='RemoteUser'; RemoteMachineAuthorizedList='RemoteMachine'
    }
    foreach ($property in $Object.CimInstanceProperties) {
        # Preserve the cmdlet's adapted enum names; unknown numeric values stay unknown
        # in Python rather than being guessed from a localized display rendering.
        $name = $property.Name
        if ($aliases.ContainsKey($name) -and $Object.PSObject.Properties[$aliases[$name]]) { $name = $aliases[$name] }
        $value = $Object.PSObject.Properties[$name].Value
        if ($null -eq $value) { $fields[$name] = $null }
        else { $fields[$name] = @($value | ForEach-Object { [string] $_ }) }
    }
    return $fields
}
