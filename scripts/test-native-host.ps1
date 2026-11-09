[CmdletBinding()]
param(
    [string]$CMake = 'cmake',
    [string]$Generator = '',
    [switch]$KeepBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) {
    throw 'This entry point requires 64-bit Windows. On Linux, configure native/ with CMake and run CTest.'
}
if ($Generator -and $Generator -notmatch '^Visual Studio ') {
    throw 'Use a Visual Studio generator with the installed MSVC C11 toolchain.'
}
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$cmakeCommand = Get-Command $CMake -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $cmakeCommand -and $CMake -eq 'cmake') {
    $cmakeCommand = Get-Command (Join-Path $env:ProgramFiles 'CMake\bin\cmake.exe') -CommandType Application -ErrorAction Stop
}
if ($null -eq $cmakeCommand) { throw "Cannot find CMake: $CMake" }
$cmakePath = $cmakeCommand.Source
$ctestPath = Join-Path (Split-Path -Parent $cmakePath) 'ctest.exe'
if (-not (Test-Path -LiteralPath $ctestPath -PathType Leaf)) { throw "Cannot find CTest beside $cmakePath." }

$buildParent = [IO.Path]::GetFullPath((Join-Path $root '.build'))
$scratch = Join-Path $buildParent ('native-host-' + [Guid]::NewGuid().ToString('N'))
$reportPath = Join-Path $buildParent 'native-host-check.json'
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$tempDirectory = Join-Path $scratch 'tmp'
New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$commands = [Collections.Generic.List[object]]::new()
$report = [ordered]@{
    schema_version = 1
    checked_at_utc = [DateTime]::UtcNow.ToString('o')
    platform = 'Windows x64 / MSVC'
    passed = $false
    scope = 'Native model/ownership/address-codec checks and Windows virtual-memory adapter; no Linux guest execution.'
    cmake = $cmakePath
    configuration = 'Debug'
    commands = $commands
    tests = @()
    source_sha256 = [ordered]@{}
    excluded = @(
        'Linux ELF parser: current implementation requires Linux ELF/mmap headers; Linux CMake target is provided.',
        'Local pipe/eventfd/epoll/ppoll: requires a Linux kernel; Linux CMake target is provided.',
        'Guest thread CPU/TLS/altstack entry: requires ARM64 Linux/Android; non-ARM64 Linux CTest marks it skipped.',
        'Android app permissions, inherited seccomp, packaged runner exec and task lifecycle require app instrumentation.'
    )
    cleanup = 'pending'
}
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    $code = $LASTEXITCODE
    $commands.Add([ordered]@{ executable = $Executable; arguments = $Arguments; exit_code = $code })
    if ($code -ne 0) { throw "Native check command failed with exit code ${code}: $Executable" }
}

try {
    $env:TEMP = $tempDirectory
    $env:TMP = $tempDirectory
    $sources = @(
        'native/CMakeLists.txt', 'native/host_tests.cmake',
        'native/guest_space.c', 'native/guest_space.h', 'native/guest_space_tests.c',
        'native/guest_signals.c', 'native/guest_signals.h', 'native/guest_signals_tests.c',
        'native/guest_fds.c', 'native/guest_fds.h', 'native/guest_fds_tests.c',
        'native/guest_gates.c', 'native/guest_gates.h', 'native/guest_context.h', 'native/guest_gates_tests.c',
        'native/shell_runtime.c', 'native/linux_filter_tests.c',
        'native/network_probe.c', 'native/network_probe.h', 'native/network_probe_address_tests.c',
        'scripts/extract-linux-filter.cmake', 'scripts/test-native-host.ps1'
    )
    foreach ($source in $sources) {
        $report.source_sha256[$source] = (Get-FileHash -LiteralPath (Join-Path $root $source) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $configure = @('-S', (Join-Path $root 'native'), '-B', $scratch, '-A', 'x64')
    if ($Generator) { $configure += @('-G', $Generator) }
    Invoke-Checked -Executable $cmakePath -Arguments $configure
    # Avoid persistent MSBuild worker nodes (and their named-pipe permission
    # requirements) in restricted developer shells. These six targets are small.
    Invoke-Checked -Executable $cmakePath -Arguments @('--build', $scratch, '--config', 'Debug', '--parallel', '1', '--', '/nodeReuse:false')
    $junitPath = Join-Path $scratch 'results.xml'
    Invoke-Checked -Executable $ctestPath -Arguments @('--test-dir', $scratch, '-C', 'Debug', '--output-on-failure', '--output-junit', $junitPath)
    [xml]$junit = Get-Content -LiteralPath $junitPath -Raw
    $cases = @($junit.SelectNodes('//testcase'))
    if ($cases.Count -ne 6) { throw "Expected all six Windows check groups, found $($cases.Count)." }
    $report.tests = @($cases | ForEach-Object {
        if ($null -ne $_.SelectSingleNode('failure') -or $null -ne $_.SelectSingleNode('skipped')) {
            throw "Unexpected failed/skipped Windows check: $($_.GetAttribute('name'))"
        }
        $outputNode = $_.SelectSingleNode('system-out')
        [ordered]@{
            name = $_.GetAttribute('name')
            seconds = $_.GetAttribute('time')
            output = $(if ($null -ne $outputNode) { $outputNode.InnerText.Trim() } else { '' })
        }
    })
    $report['generated_filter_sha256'] = (Get-FileHash -LiteralPath (Join-Path $scratch 'linux_filter_generated.h') -Algorithm SHA256).Hash.ToLowerInvariant()
    $report['compiler'] = @(Get-ChildItem -LiteralPath (Join-Path $scratch 'CMakeFiles') -Recurse -File -Filter CMakeCCompiler.cmake |
        Select-Object -First 1 | Get-Content | Where-Object { $_ -match '^set\(CMAKE_C_COMPILER(_ID|_VERSION)? ' })
    # Refuse evidence for a source revision that changed while checks ran.
    foreach ($source in $sources) {
        if ((Get-FileHash -LiteralPath (Join-Path $root $source) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $report.source_sha256[$source]) {
            throw "Source changed during native checks; rerun: $source"
        }
    }
    $report.passed = $true
}
catch {
    $report['error'] = $_.Exception.Message
    throw
}
finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    try {
        if ($KeepBuild) {
            $report.cleanup = 'retained by -KeepBuild'
            $report['build_directory'] = $scratch
        } else {
            $resolvedScratch = (Resolve-Path -LiteralPath $scratch).Path
            $prefix = $buildParent.TrimEnd('\') + '\'
            if (-not $resolvedScratch.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
                (Split-Path -Leaf $resolvedScratch) -notmatch '^native-host-[0-9a-f]{32}$') {
                throw 'Refusing cleanup outside the unique native-host build directory.'
            }
            $entries = @((Get-Item -LiteralPath $resolvedScratch)) + @(Get-ChildItem -LiteralPath $resolvedScratch -Force -Recurse)
            if (@($entries | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -gt 0) {
                throw 'Refusing recursive cleanup through a reparse point.'
            }
            Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
            $report.cleanup = 'unique build directory removed'
        }
    } finally {
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
    }
}
Write-Host "Six Windows native check groups passed. Evidence: $reportPath"
