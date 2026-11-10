[CmdletBinding()]
param([ValidateRange(1,60)][int] $Minutes = 10, [string] $WindowEndUtc = '')
. (Join-Path $PSScriptRoot 'Collection.Common.ps1')
$windowEnd = [DateTimeOffset]::UtcNow
if ($WindowEndUtc) { $windowEnd = [DateTimeOffset]::Parse($WindowEndUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None) }
$windowStart = $windowEnd.AddMinutes(-$Minutes)
Start-Source 'events' ($windowStart.ToString('o')) ($windowEnd.ToString('o'))
$count = 0
$state = 'complete'
$codes = @()
try {
    $channel = Get-WinEvent -ListLog Security -ErrorAction Stop
    if (-not $channel.IsEnabled) {
        Finish-Source 'events' 'unavailable' 0 @('SECURITY_CHANNEL_DISABLED')
        exit 0
    }
    # Read one extra match to distinguish exactly-at-cap from real truncation.
    $filter = @{ LogName='Security'; Id=@(5157,5152); StartTime=$windowStart.UtcDateTime; EndTime=$windowEnd.UtcDateTime }
    Get-WinEvent -FilterHashtable $filter -MaxEvents 100001 -ErrorAction Stop | ForEach-Object {
        $event = $_
        try {
            if ($count -ge 100000) { throw [IO.InvalidDataException]::new('Event count cap') }
            $xml = $event.ToXml()
            if ([Text.Encoding]::UTF8.GetByteCount($xml) -gt 65536) { throw [IO.InvalidDataException]::new('Event XML byte cap') }
            Write-Frame @{ kind='record'; source='events'; data=$xml }
            $count++
        }
        finally { $event.Dispose() }
    }
}
catch {
    if ($count -eq 0 -and ($_.FullyQualifiedErrorId -split ',')[0] -eq 'NoMatchingEventsFound') { $state = 'empty' }
    else { $state = Get-FailureState $_; $codes += 'EVENT_ENUMERATION_INCOMPLETE' }
}
if ($state -eq 'complete' -and $count -eq 0) { $state = 'empty' }
Finish-Source 'events' $state $count $codes
