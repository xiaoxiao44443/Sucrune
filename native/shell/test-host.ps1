[CmdletBinding()]
param(
    [string]$Compiler,
    [string]$WindowsSdkRoot = (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'),
    [string]$WindowsSdkVersion
)
$ErrorActionPreference = 'Stop'
if (-not $Compiler) {
    $command = Get-Command cl.exe -ErrorAction Stop
    $Compiler = $command.Path
}
$Compiler = (Resolve-Path -LiteralPath $Compiler).Path
$vcHome = [IO.Directory]::GetParent([IO.Path]::GetDirectoryName($Compiler)).Parent.Parent.FullName
if (-not (Test-Path -LiteralPath (Join-Path $vcHome 'include\stdint.h'))) {
    throw 'Pass an MSVC bin\Hostx64\x64\cl.exe compiler.'
}
$WindowsSdkRoot = (Resolve-Path -LiteralPath $WindowsSdkRoot).Path
if (-not $WindowsSdkVersion) {
    $candidate = Get-ChildItem -LiteralPath (Join-Path $WindowsSdkRoot 'Include') -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'ucrt\stdio.h') } |
        Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    if ($null -eq $candidate) { throw 'A Windows SDK with UCRT headers is required.' }
    $WindowsSdkVersion = $candidate.Name
}
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$buildDirectory = Join-Path $projectRoot '.build\shell-host-tests'
New-Item -ItemType Directory -Force -Path $buildDirectory | Out-Null
$objectPath = Join-Path $buildDirectory 'tests-host.obj'
$executablePath = Join-Path $buildDirectory 'tests-host.exe'
$names = @('INCLUDE', 'LIB', 'TEMP', 'TMP')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:INCLUDE = "$vcHome\include;$WindowsSdkRoot\Include\$WindowsSdkVersion\ucrt;$WindowsSdkRoot\Include\$WindowsSdkVersion\shared;$WindowsSdkRoot\Include\$WindowsSdkVersion\um"
    $env:LIB = "$vcHome\lib\x64;$WindowsSdkRoot\Lib\$WindowsSdkVersion\ucrt\x64;$WindowsSdkRoot\Lib\$WindowsSdkVersion\um\x64"
    $env:TEMP = $buildDirectory
    $env:TMP = $buildDirectory
    & $Compiler /nologo /std:c11 /W4 /WX /Od /GS- /Oi- /TC "/Fo$objectPath" "/Fe$executablePath" (Join-Path $PSScriptRoot 'tests_host.c')
    if ($LASTEXITCODE -ne 0) { throw "Host shell regression build failed: $LASTEXITCODE" }
    & $executablePath
    if ($LASTEXITCODE -ne 0) { throw "Host shell regression failed: $LASTEXITCODE" }
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
