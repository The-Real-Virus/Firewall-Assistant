[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'Collection.Common.ps1')
Start-Source 'host'
try {
    $system = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $architecture = 'unknown'
    if ($processor.Architecture -eq 9) { $architecture = 'x64' }
    elseif ($processor.Architecture -eq 12) { $architecture = 'arm64' }
    elseif ($processor.Architecture -eq 0) { $architecture = 'x86' }
    Write-Frame @{ kind='record'; source='host'; data=@{
        schema_version='1.0'; os='windows'; edition=[string]$current.EditionID
        build=([string]$current.CurrentBuildNumber + '.' + [string]$current.UBR)
        architecture=$architecture; supported_build=$false; hostname=[Environment]::MachineName
        windows_product_type=[int]$system.ProductType
    } }
    Finish-Source 'host' 'complete' 1
}
catch { Finish-Source 'host' (Get-FailureState $_) 0 @('HOST_METADATA_UNAVAILABLE') }
Start-Source 'network'
$networkCount = 0
try {
    Import-SystemModule 'NetTCPIP'
    Import-SystemModule 'NetAdapter'
    Import-SystemModule 'NetConnection'
    $connections = @(Get-NetConnectionProfile -ErrorAction Stop)
    $addresses = @(Get-NetIPAddress -ErrorAction Stop)
    Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
        if ($networkCount -ge 512) { throw [IO.InvalidDataException]::new('Interface cap') }
        $adapter = $_
        $category = @($connections | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | Select-Object -ExpandProperty NetworkCategory -Unique)
        $profile = $null
        if ($category.Count -eq 1) {
            if ([string]$category[0] -eq 'DomainAuthenticated') { $profile = 'Domain' }
            elseif ([string]$category[0] -in @('Private','Public')) { $profile = [string]$category[0] }
        }
        $ips = @($addresses | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | ForEach-Object {
            $address = [string]$_.IPAddress
            if ($address.Contains('%')) {
                $parts = $address.Split('%')
                if ($parts.Count -ne 2 -or $parts[1] -ne [string]$adapter.ifIndex -or
                    ([Net.IPAddress]::Parse($parts[0])).AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) {
                    throw [IO.InvalidDataException]::new('Address interface scope differs')
                }
                # The separately recorded interface_index retains this scope.
                $address = $parts[0]
            }
            $address
        } | Select-Object -Unique)
        if ($ips.Count -gt 100) { throw [IO.InvalidDataException]::new('Address cap') }
        $linkState = 'unknown'
        if ([string]$adapter.Status -eq 'Up') { $linkState = 'up' }
        elseif ([string]$adapter.Status -eq 'Disconnected' -or [string]$adapter.Status -eq 'Disabled') { $linkState = 'down' }
        Write-Frame @{ kind='record'; source='network'; data=@{
            interface_index=[int]$adapter.ifIndex; name=[string]$adapter.Name
            addresses=@($ips); active_profile=$profile; state=$linkState
            source_ref=('network:' + [string]($networkCount + 1))
        } }
        $networkCount++
    }
    $networkState = 'complete'
    if ($networkCount -eq 0) { $networkState = 'empty' }
    Finish-Source 'network' $networkState $networkCount
}
catch { Finish-Source 'network' (Get-FailureState $_) $networkCount @('NETWORK_METADATA_INCOMPLETE') }
