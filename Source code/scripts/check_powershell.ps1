$ErrorActionPreference = 'Stop'
$resourceRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\wfdiag\resources\powershell'
$files = @(Get-ChildItem -LiteralPath $resourceRoot -Filter '*.ps1' -File)
if ($files.Count -eq 0) { throw 'Required PowerShell resources are missing.' }
foreach ($file in $files) {
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        $parseErrors | ForEach-Object { Write-Error $_.Message }
        exit 1
    }
}
Write-Output "Parsed $($files.Count) PowerShell resource files. No resource was executed."
