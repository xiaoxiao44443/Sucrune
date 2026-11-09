[CmdletBinding()]
param(
    [string]$Go = 'go',
    [switch]$Race
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$goCommand = (Get-Command $Go -CommandType Application -ErrorAction Stop).Source
$goDirectory = Split-Path -Parent $goCommand
$isWindowsHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$gofmtName = if ($isWindowsHost) { 'gofmt.exe' } else { 'gofmt' }
$gofmtCommand = Join-Path $goDirectory $gofmtName
if (-not (Test-Path -LiteralPath $gofmtCommand -PathType Leaf)) {
    throw "Cannot locate $gofmtName alongside $goCommand."
}

$buildRoot = Join-Path $projectRoot '.build'
$paths = @{
    GOCACHE = Join-Path $buildRoot 'go-cache'
    GOMODCACHE = Join-Path $buildRoot 'go-mod-cache'
    TEMP = Join-Path $buildRoot 'test-tmp'
    TMP = Join-Path $buildRoot 'test-tmp'
}
foreach ($directory in $paths.Values) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}
$binDirectory = Join-Path $buildRoot 'bin'
New-Item -ItemType Directory -Force -Path $binDirectory | Out-Null
$environmentKeys = @('GOCACHE', 'GOMODCACHE', 'TEMP', 'TMP', 'GOTOOLCHAIN', 'GOENV')
$previousEnvironment = @{}
foreach ($name in $environmentKeys) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Invoke-Go {
    param([string[]]$Arguments)
    & $goCommand @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("Go command failed with exit code {0}: go {1}" -f $LASTEXITCODE, ($Arguments -join ' '))
    }
}

Push-Location -LiteralPath $projectRoot
try {
    foreach ($name in $paths.Keys) {
        [Environment]::SetEnvironmentVariable($name, $paths[$name], 'Process')
    }
    $env:GOTOOLCHAIN = 'local'
    $env:GOENV = 'off'
    Invoke-Go -Arguments @('version')

    $sourceFiles = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'cmd'), (Join-Path $projectRoot 'internal') -Recurse -File -Filter '*.go' | ForEach-Object FullName)
    $formatIssues = @(& $gofmtCommand -l @sourceFiles)
    if ($LASTEXITCODE -ne 0) {
        throw "gofmt failed with exit code $LASTEXITCODE."
    }
    if ($formatIssues.Count -gt 0) {
        throw "Run gofmt on these files before testing: $($formatIssues -join ', ')"
    }

    Invoke-Go -Arguments @('vet', './...')
    $testArguments = @('test', '-count=1')
    if ($Race) { $testArguments += '-race' }
    $testArguments += './...'
    Invoke-Go -Arguments $testArguments

    $binaryName = if ($isWindowsHost) { 'sucrune.exe' } else { 'sucrune' }
    $binaryPath = Join-Path $binDirectory $binaryName
    Invoke-Go -Arguments @('build', '-o', $binaryPath, './cmd/sucrune')
    Write-Host "Core checks passed. CLI: $binaryPath"
    if ($Race) {
        Write-Host 'Race detector was enabled.'
    }
}
finally {
    foreach ($name in $environmentKeys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    Pop-Location
}
