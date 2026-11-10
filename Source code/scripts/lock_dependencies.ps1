param(
    [string]$CandidateConstraints = ''
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
if ((Get-Location).Path -ne $taskRoot) { throw 'Run from the verified Product root.' }
$taskPython = Join-Path $taskRoot '.venv\Scripts\python.exe'
& $taskPython -c "import sys,struct; assert sys.version_info[:2]==(3,13); assert struct.calcsize('P')==8"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 x64 verification failed.' }
$oldPipCache = $env:PIP_CACHE_DIR
$oldToolsCache = $env:PIP_TOOLS_CACHE_DIR
$oldCompileCommand = $env:CUSTOM_COMPILE_COMMAND
try {
    $env:PIP_CACHE_DIR = Join-Path $taskRoot '.build\cache\pip'
    $env:PIP_TOOLS_CACHE_DIR = Join-Path $taskRoot '.build\cache\pip-tools'
    $env:CUSTOM_COMPILE_COMMAND = 'powershell -NoProfile -File scripts/lock_dependencies.ps1'
    $candidateArgs = @()
    if ($CandidateConstraints) {
        if (-not (Test-Path -LiteralPath $CandidateConstraints -PathType Leaf)) { throw 'Candidate constraint file is missing.' }
        $candidateArgs = @('--constraint', $CandidateConstraints)
    }
    & $taskPython -m piptools compile pyproject.toml --generate-hashes --allow-unsafe --strip-extras --output-file requirements.txt @candidateArgs
    if ($LASTEXITCODE -ne 0) { throw 'Core lock resolution failed.' }
    & $taskPython -m piptools compile pyproject.toml --extra desktop --extra ai --constraint requirements.txt --generate-hashes --allow-unsafe --strip-extras --output-file requirements-desktop-ai.txt @candidateArgs
    if ($LASTEXITCODE -ne 0) { throw 'Integrated runtime lock resolution failed.' }
    & $taskPython -m piptools compile pyproject.toml --extra desktop --extra ai --extra dev --extra desktop-test --constraint requirements-desktop-ai.txt --generate-hashes --allow-unsafe --strip-extras --output-file requirements-dev.txt @candidateArgs
    if ($LASTEXITCODE -ne 0) { throw 'Development lock resolution failed.' }
}
finally {
    $env:PIP_CACHE_DIR = $oldPipCache
    $env:PIP_TOOLS_CACHE_DIR = $oldToolsCache
    $env:CUSTOM_COMPILE_COMMAND = $oldCompileCommand
}
