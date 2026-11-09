[CmdletBinding()]
param(
    [string]$Compiler = 'cc',
    [switch]$Msvc
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourcePath = Join-Path $root 'native\shell_runtime.c'
$testPath = Join-Path $root 'native\linux_filter_tests.c'
$scratch = Join-Path $root '.build\linux-filter-check'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$source = Get-Content -LiteralPath $sourcePath -Raw
$start = $source.IndexOf('static size_t filter_range(')
$end = if ($start -ge 0) { $source.IndexOf('static int guarded(', $start) } else { -1 }
if ($start -lt 0 -or $end -le $start) { throw 'Cannot identify the real Linux filter generator in shell_runtime.c.' }
$tag = [regex]::Match($source, '(?m)^#define SHELL_TAG[^\r\n]+')
if (-not $tag.Success) { throw 'Cannot identify the actual seccomp tag.' }
$generated = $tag.Value + "`n" + $source.Substring($start, $end - $start)
$generatedPath = Join-Path $scratch 'linux_filter_generated.h'
[IO.File]::WriteAllText($generatedPath, $generated, [Text.UTF8Encoding]::new($false))
$isWindowsHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$binary = Join-Path $scratch $(if ($isWindowsHost) { 'linux-filter-tests.exe' } else { 'linux-filter-tests' })
$compilerPath = (Get-Command $Compiler -CommandType Application -ErrorAction Stop).Source
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
try {
    $env:TEMP = $scratch
    $env:TMP = $scratch
    if ($Msvc) {
        $arguments = @('/nologo','/std:c11','/W4','/WX','/Od',"/I$scratch", "/Fe:$binary", "/Fo:$(Join-Path $scratch 'linux-filter-tests.obj')", $testPath)
    } else {
        $arguments = @('-std=c11','-Wall','-Wextra','-Werror','-Wconversion','-Wshadow','-O2','-I',$scratch,$testPath,'-o',$binary)
    }
    & $compilerPath @arguments
    if ($LASTEXITCODE -ne 0) { throw "Filter interpreter compilation failed: $LASTEXITCODE" }
    $output = @(& $binary)
    if ($LASTEXITCODE -ne 0) { throw "Filter interpreter checks failed: $LASTEXITCODE" }
    $line = $output -join "`n"
    $result = [regex]::Match($line, 'Linux filter checks: (\d+) decisions across (\d+) source-generated configurations passed\.')
    if (-not $result.Success) { throw 'Missing successful filter check summary.' }
    [ordered]@{
        schema_version = 1
        scope = 'Classic BPF interpreter runs instructions emitted by the actual source generator; no kernel filter installation.'
        passed = $true
        decisions = [int]$result.Groups[1].Value
        configurations = [int]$result.Groups[2].Value
        expected_guest_resume_pc = 'low < PC <= high; AArch64 SVC is at PC - 4'
        source_file = 'native/shell_runtime.c'
        source_sha256 = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
        generated_functions_sha256 = (Get-FileHash -LiteralPath $generatedPath -Algorithm SHA256).Hash
        test_sha256 = (Get-FileHash -LiteralPath $testPath -Algorithm SHA256).Hash
        result = $line
        limitations = @('Does not establish Android inherited filter precedence or kernel behavior.', 'Does not execute a guest or prove hostile-code isolation.')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root '.build\linux-filter-check.json') -Encoding utf8
    Write-Output $line
} finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
}
