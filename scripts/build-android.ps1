[CmdletBinding()]
param(
    [string]$JdkHome = $env:JAVA_HOME,
    [string]$SdkRoot = $env:ANDROID_HOME,
    [string]$CMakeHome,
    [string]$CMakeVersion,
    [string]$NinjaHome,
    [string]$Gradle,
    [string]$ReadOnlyGradleCache,
    [string]$Go = 'go',
    [string]$Zig = 'zig',
    [ValidateSet('debug', 'validation')]
    [string]$Variant = 'debug',
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'
$Variant = $Variant.ToLowerInvariant()
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $SdkRoot) { $SdkRoot = $env:ANDROID_SDK_ROOT }
if (-not $JdkHome -or -not (Test-Path -LiteralPath (Join-Path $JdkHome 'bin\java.exe'))) {
    throw 'Set JAVA_HOME or pass -JdkHome to a JDK 17 or newer.'
}
if (-not $SdkRoot -or -not (Test-Path -LiteralPath $SdkRoot)) {
    throw 'Set ANDROID_HOME or pass -SdkRoot to an installed Android SDK.'
}
if ($CMakeHome -and -not (Test-Path -LiteralPath (Join-Path $CMakeHome 'bin\cmake.exe'))) {
    throw '-CMakeHome must contain bin\cmake.exe.'
}
if (-not $Gradle) { $Gradle = Join-Path $projectRoot 'gradlew.bat' }
if (-not (Test-Path -LiteralPath $Gradle)) { throw 'The Gradle launcher was not found.' }
$JdkHome = (Resolve-Path -LiteralPath $JdkHome).Path
$SdkRoot = (Resolve-Path -LiteralPath $SdkRoot).Path
$Gradle = (Resolve-Path -LiteralPath $Gradle).Path
if ($CMakeHome) { $CMakeHome = (Resolve-Path -LiteralPath $CMakeHome).Path }
if ($NinjaHome) {
    $NinjaHome = (Resolve-Path -LiteralPath $NinjaHome).Path
    if (-not (Test-Path -LiteralPath (Join-Path $NinjaHome 'ninja.exe'))) { throw '-NinjaHome must contain ninja.exe.' }
}
if ($ReadOnlyGradleCache) {
    $ReadOnlyGradleCache = (Resolve-Path -LiteralPath $ReadOnlyGradleCache).Path
    if (-not (Test-Path -LiteralPath (Join-Path $ReadOnlyGradleCache 'modules-2'))) {
        throw '-ReadOnlyGradleCache must be the directory containing modules-2.'
    }
}

function ConvertTo-JavaPropertyValue([string]$Value) {
    $encoded = [Text.StringBuilder]::new()
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { [void]$encoded.Append('\\') }
        elseif ($character -eq ':') { [void]$encoded.Append('\:') }
        elseif ([int]$character -lt 32 -or [int]$character -gt 126) {
            [void]$encoded.Append(('\u{0:x4}' -f [int]$character))
        } else { [void]$encoded.Append($character) }
    }
    return $encoded.ToString()
}

# Local tool locations stay out of version control. Preserve unrelated settings.
$propertiesPath = Join-Path $projectRoot 'local.properties'
$properties = @()
if (Test-Path -LiteralPath $propertiesPath) {
    $previousProperties = @(Get-Content -LiteralPath $propertiesPath)
    if (-not $CMakeVersion -and -not $CMakeHome) {
        foreach ($line in $previousProperties) {
            if ($line -match '^\s*sucrune\.cmakeVersion\s*[=:]\s*(\S+)\s*$') { $CMakeVersion = $Matches[1] }
        }
    }
    $properties = @($previousProperties | Where-Object {
        $_ -notmatch '^\s*sdk\.dir\s*[=:]' -and $_ -notmatch '^\s*sucrune\.cmakeVersion\s*[=:]' -and (-not $CMakeHome -or $_ -notmatch '^\s*cmake\.dir\s*[=:]')
    })
}
if (-not $CMakeVersion -and $CMakeHome) {
    $versionOutput = & (Join-Path $CMakeHome 'bin\cmake.exe') --version
    if ($LASTEXITCODE -ne 0 -or $versionOutput[0] -notmatch '^cmake version (\S+)') {
        throw 'Cannot determine the selected CMake version.'
    }
    $CMakeVersion = $Matches[1]
}
if (-not $CMakeVersion) { $CMakeVersion = '3.22.1' }
$properties += 'sdk.dir=' + (ConvertTo-JavaPropertyValue $SdkRoot.Replace('\', '/'))
if ($CMakeHome) { $properties += 'cmake.dir=' + (ConvertTo-JavaPropertyValue $CMakeHome.Replace('\', '/')) }
$properties += 'sucrune.cmakeVersion=' + $CMakeVersion
[IO.File]::WriteAllText($propertiesPath, ($properties -join "`n") + "`n", [Text.UTF8Encoding]::new($false))

$variables = @('JAVA_HOME','ANDROID_HOME','ANDROID_USER_HOME','GRADLE_USER_HOME','GRADLE_RO_DEP_CACHE','TEMP','TMP','Path')
$previous = @{}
foreach ($name in $variables) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:JAVA_HOME = $JdkHome
    $env:ANDROID_HOME = $SdkRoot
    $env:ANDROID_USER_HOME = Join-Path $projectRoot '.build\android-user'
    $env:GRADLE_USER_HOME = Join-Path $projectRoot '.build\gradle-home'
    $env:TEMP = Join-Path $projectRoot '.build\temp'
    $env:TMP = $env:TEMP
    foreach ($directory in @($env:ANDROID_USER_HOME,$env:GRADLE_USER_HOME,$env:TEMP)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    if ($ReadOnlyGradleCache) { $env:GRADLE_RO_DEP_CACHE = $ReadOnlyGradleCache }
    if ($NinjaHome) { $env:Path = $NinjaHome + [IO.Path]::PathSeparator + $env:Path }
    & (Join-Path $PSScriptRoot 'build-linux-programs.ps1') -Zig $Zig
    & (Join-Path $PSScriptRoot 'build-go-android.ps1') -Go $Go -SdkRoot $SdkRoot
    $arguments = @('--no-daemon', "-Psucrune.cmakeVersion=$CMakeVersion", "-Psucrune.testBuildType=$Variant")
    if ($Offline) { $arguments += '--offline' }
    $taskVariant = $Variant.Substring(0, 1).ToUpperInvariant() + $Variant.Substring(1)
    $arguments += @((":probeapp:assemble" + $taskVariant), (":probeapp:assemble" + $taskVariant + 'AndroidTest'), (":probeapp:lint" + $taskVariant))
    Push-Location $projectRoot
    try {
        & $Gradle @arguments
        if ($LASTEXITCODE -ne 0) { throw "Android build failed with exit code $LASTEXITCODE." }
    } finally { Pop-Location }
    Write-Output ('Probe APK: ' + (Join-Path $projectRoot "android\probeapp\build\outputs\apk\$Variant\probeapp-$Variant.apk"))
    Write-Output ('Test APK: ' + (Join-Path $projectRoot "android\probeapp\build\outputs\apk\androidTest\$Variant\probeapp-$Variant-androidTest.apk"))
    Write-Output 'Compilation is complete. Device probe behavior still requires execution on Android.'
} finally {
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
