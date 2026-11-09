param(
    [string] $Java = 'java',
    [string] $GradleCache = (Join-Path $env:USERPROFILE '.gradle\caches\modules-2\files-2.1')
)
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = Join-Path $project '.build'
$scratch = Join-Path $buildRoot ('secrets-check-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($scratch) | Out-Null
$report = $null
$reportPath = Join-Path $buildRoot 'execution-secrets-check.json'
function Find-Jar([string] $relative) {
    $found = Get-ChildItem -LiteralPath (Join-Path $GradleCache $relative) -Recurse -File -Filter '*.jar' | Select-Object -First 1
    if (-not $found) { throw "Missing Kotlin compiler dependency: $relative" }
    return $found.FullName
}
function Run-Java([string[]] $Arguments) {
    $output = (& $Java @Arguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Synthetic secret host check failed ($LASTEXITCODE):`n$output" }
    return $output.Trim()
}
try {
    $stdlib = Find-Jar 'org.jetbrains.kotlin\kotlin-stdlib\2.0.21'
    $annotations = Find-Jar 'org.jetbrains\annotations\23.0.0'
    $compiler = @(
        (Find-Jar 'org.jetbrains.kotlin\kotlin-compiler-embeddable\2.0.21'), $stdlib,
        (Find-Jar 'org.jetbrains.kotlin\kotlin-script-runtime\2.0.21'),
        (Find-Jar 'org.jetbrains.kotlin\kotlin-reflect\1.9.23'),
        (Find-Jar 'org.jetbrains.intellij.deps\trove4j'),
        (Find-Jar 'org.jetbrains.kotlinx\kotlinx-coroutines-core-jvm\1.9.0'), $annotations
    ) -join [IO.Path]::PathSeparator
    $helper = Join-Path $project 'android\probeapp\src\main\kotlin\com\sucrune\probe\ExecutionSecrets.kt'
    $test = Join-Path $PSScriptRoot 'tests\ExecutionSecretsTests.kt'
    $sources = @($helper, $test, $PSCommandPath)
    $before = @{}
    foreach ($path in $sources) { $before[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    $classes = Join-Path $scratch 'classes'
    $compiled = Run-Java @('-cp', $compiler, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
        '-jvm-target', '17', '-Werror', '-classpath', "$stdlib;$annotations", '-d', $classes, $helper, $test)
    $tested = Run-Java @('-Xmx256m', '-cp', "$classes;$stdlib", 'com.sucrune.probe.ExecutionSecretsTestsKt')
    Write-Output $tested
    $sourceHashes = [ordered]@{}
    foreach ($path in $sources) {
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $before[$path]) {
            throw 'Secret helper sources changed during the host checks'
        }
        $sourceHashes[$path.Substring($project.Length + 1).Replace('\', '/')] = $before[$path]
    }
    $report = [ordered]@{
        schema_version = 1
        scope = 'Windows pure JVM synthetic secret admission/copy/lifecycle/stream redaction tests only; no real credentials, IPC, JNI or Android runtime claim'
        time_utc = [DateTime]::UtcNow.ToString('o')
        compiler = 'Kotlin 2.0.21; JVM 17; warnings as errors; test heap 256 MiB'
        compile_output = $compiled
        tests = $tested
        source_sha256 = $sourceHashes
        scratch_removed = $false
    }
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath($buildRoot) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^secrets-check-[0-9a-f]{32}$') {
        throw 'Refusing cleanup outside this unique secret host check directory'
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    if (Test-Path -LiteralPath $resolved) { throw 'Secret host check scratch cleanup was not confirmed' }
    if ($null -ne $report) {
        $report.scratch_removed = $true
        $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding utf8
    }
}
