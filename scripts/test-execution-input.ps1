param(
    [string] $Java = 'java',
    [string] $GradleCache = (Join-Path $env:USERPROFILE '.gradle\caches\modules-2\files-2.1'),
    [string] $AndroidJar = ''
)
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = Join-Path $project '.build'
[IO.Directory]::CreateDirectory($buildRoot) | Out-Null
$scratch = Join-Path $buildRoot ('input-check-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($scratch) | Out-Null
$report = $null
$reportPath = Join-Path $buildRoot 'execution-input-check.json'

function Find-Jar([string] $relative) {
    $found = Get-ChildItem -LiteralPath (Join-Path $GradleCache $relative) -Recurse -File -Filter '*.jar' |
        Select-Object -First 1
    if (-not $found) { throw "Missing Kotlin compiler dependency: $relative" }
    return $found.FullName
}
function Run-Java([string[]] $Arguments) {
    $output = (& $Java @Arguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Java command failed ($LASTEXITCODE):`n$output" }
    return $output.Trim()
}

try {
    $stdlib = Find-Jar 'org.jetbrains.kotlin\kotlin-stdlib\2.0.21'
    $annotations = Find-Jar 'org.jetbrains\annotations\23.0.0'
    $compiler = @(
        (Find-Jar 'org.jetbrains.kotlin\kotlin-compiler-embeddable\2.0.21'),
        $stdlib,
        (Find-Jar 'org.jetbrains.kotlin\kotlin-script-runtime\2.0.21'),
        (Find-Jar 'org.jetbrains.kotlin\kotlin-reflect\1.9.23'),
        (Find-Jar 'org.jetbrains.intellij.deps\trove4j'),
        (Find-Jar 'org.jetbrains.kotlinx\kotlinx-coroutines-core-jvm\1.9.0'),
        $annotations
    ) -join [IO.Path]::PathSeparator
    $sourceRoot = Join-Path $project 'android\probeapp\src\main\kotlin\com\sucrune\probe'
    $inputSource = Join-Path $sourceRoot 'ExecutionInput.kt'
    $testSource = Join-Path $PSScriptRoot 'tests\ExecutionInputTests.kt'
    $sources = @($inputSource, $testSource, $PSCommandPath)
    if ($AndroidJar) {
        if (-not (Test-Path -LiteralPath $AndroidJar -PathType Leaf)) { throw 'AndroidJar does not exist' }
        $stdoutTest = Join-Path $PSScriptRoot 'tests\ExecutionStdoutTests.kt'
        $admissionTest = Join-Path $PSScriptRoot 'tests\RuntimeAdmissionTests.kt'
        $sources += @($stdoutTest, $admissionTest)
        $sources += @('NativeProbe.kt', 'RuntimeClient.kt', 'RuntimeWorkerService.kt', 'ExecutionSecrets.kt', 'ExecutionStdout.kt') |
            ForEach-Object { Join-Path $sourceRoot $_ }
    }
    $before = @{}
    foreach ($path in $sources) { $before[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    $common = @('-cp', $compiler, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
        '-jvm-target', '17', '-Werror')
    $classes = Join-Path $scratch 'classes'
    $compileOutput = Run-Java ($common + @('-classpath', "$stdlib;$annotations", '-d', $classes, $inputSource, $testSource))
    $testOutput = Run-Java @('-cp', "$classes;$stdlib", 'com.sucrune.probe.ExecutionInputTestsKt')
    Write-Output $testOutput
    $androidOutput = ''
    if ($AndroidJar) {
        $androidOutput = Run-Java ($common + @('-classpath', "$AndroidJar;$stdlib;$annotations", '-d',
            (Join-Path $scratch 'android-classes'), $inputSource, $stdoutTest, $admissionTest) + @('NativeProbe.kt', 'RuntimeClient.kt', 'RuntimeWorkerService.kt', 'ExecutionSecrets.kt', 'ExecutionStdout.kt').ForEach({ Join-Path $sourceRoot $_ }))
        $stdoutResult = Run-Java @('-cp', "$(Join-Path $scratch 'android-classes');$stdlib;$AndroidJar", 'com.sucrune.probe.ExecutionStdoutTestsKt')
        Write-Output $stdoutResult
        $admissionResult = Run-Java @('-cp', "$(Join-Path $scratch 'android-classes');$stdlib;$AndroidJar", 'com.sucrune.probe.RuntimeAdmissionTestsKt')
        Write-Output $admissionResult
        $androidOutput += $stdoutResult + $admissionResult
        Write-Output 'PASS actual RuntimeClient/ExecutionInput/RuntimeWorkerService/NativeProbe strict Kotlin compile'
    }
    foreach ($path in $sources) {
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $before[$path]) {
            throw "Source changed during checks: $path"
        }
    }
    $sourceHashes = [ordered]@{}
    foreach ($path in $sources) { $sourceHashes[$path.Substring($project.Length + 1).Replace('\', '/')] = $before[$path] }
    $report = [ordered]@{
        schema_version = 1
        scope = 'Windows JVM input queue/state tests and optional Android API signature compilation; no device or FD capability claim'
        time_utc = [DateTime]::UtcNow.ToString('o')
        compiler = 'Kotlin 2.0.21, JVM target 17, warnings as errors'
        compile_output = $compileOutput
        tests = $testOutput
        android_signature_compile = [bool]$AndroidJar
        android_compile_output = $androidOutput
        source_sha256 = $sourceHashes
        scratch_removed = $false
    }
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding utf8
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath($buildRoot) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^input-check-[0-9a-f]{32}$') {
        throw 'Refusing cleanup outside the unique input check directory'
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    if (Test-Path -LiteralPath $resolved) { throw 'Input check scratch cleanup was not confirmed' }
    if ($null -ne $report) {
        $report.scratch_removed = $true
        $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding utf8
    }
}
