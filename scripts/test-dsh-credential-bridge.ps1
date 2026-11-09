param(
    [Parameter(Mandatory=$true)][string] $AndroidJar,
    [string] $Java = 'java',
    [string] $Node = 'node',
    [string] $YamlDirectory = '',
    [string] $GradleCache = (Join-Path $env:USERPROFILE '.gradle\caches\modules-2\files-2.1')
)
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $YamlDirectory) { $YamlDirectory = Join-Path $project '.build\dsh-prep-study\node_modules\yaml' }
$buildRoot = Join-Path $project '.build'
$scratch = Join-Path $buildRoot ('credential-wire-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($scratch) | Out-Null
$report = $null
function Find-Jar([string] $relative) {
    $found = Get-ChildItem -LiteralPath (Join-Path $GradleCache $relative) -Recurse -File -Filter '*.jar' | Select-Object -First 1
    if (-not $found) { throw "Missing Kotlin compiler dependency: $relative" }
    return $found.FullName
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
    $bridge = Join-Path $project 'android\probeapp\src\androidTest\kotlin\com\sucrune\probe\tests\DshCredentialBridge.kt'
    $androidProbe = Join-Path $project 'android\probeapp\src\androidTest\kotlin\com\sucrune\probe\tests\CredentialBridgeChecks.kt'
    $peer = Join-Path $PSScriptRoot 'tests\DshCredentialWireHost.kt'
    $sender = Join-Path $PSScriptRoot 'send-dsh-credential.cjs'
    $syntheticSender = Join-Path $PSScriptRoot 'send-dsh-credential-synthetic.cjs'
    $test = Join-Path $PSScriptRoot 'tests\dsh-credential-wire.cjs'
    $paths = @($bridge, $androidProbe, $peer, $sender, $syntheticSender, $test, $PSCommandPath)
    $before = @{}
    foreach ($p in $paths) { $before[$p] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
    $classes = Join-Path $scratch 'classes'
    & $Java -cp $compiler 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler' -no-stdlib -no-reflect -jvm-target 17 -Werror `
        -classpath "$AndroidJar;$stdlib;$annotations" -d $classes $bridge $androidProbe $peer
    if ($LASTEXITCODE -ne 0) { throw 'Credential receiver strict Kotlin compilation failed' }
    $tested = (& $Node $test $Java "$classes;$stdlib" $YamlDirectory 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Synthetic credential interop test failed: $tested" }
    Write-Output $tested
    $hashes = [ordered]@{}
    foreach ($p in $paths) {
        if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $before[$p]) { throw 'Source changed during credential checks' }
        $hashes[$p.Substring($project.Length + 1).Replace('\','/')] = $before[$p]
    }
    $report = [ordered]@{
        schema_version = 1
        time_utc = [DateTime]::UtcNow.ToString('o')
        scope = 'Actual host Node sender + portable receiver under JVM over 127.0.0.1 using synthetic keys only. Android API compiled; no device, peer UID, ADB, real credential or model execution claim.'
        compiler = 'Kotlin 2.0.21; JVM 17; Android 37; -Werror'
        tests = $tested
        source_sha256 = $hashes
        scratch_removed = $false
    }
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    if ([IO.Path]::GetDirectoryName($resolved) -ne [IO.Path]::GetFullPath($buildRoot) -or
        [IO.Path]::GetFileName($resolved) -notmatch '^credential-wire-[0-9a-f]{32}$') { throw 'Unsafe credential test scratch path' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    if (Test-Path -LiteralPath $resolved) { throw 'Credential test scratch cleanup failed' }
    if ($null -ne $report) {
        $report.scratch_removed = $true
        $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $buildRoot 'dsh-credential-wire-check.json') -Encoding utf8
    }
}
