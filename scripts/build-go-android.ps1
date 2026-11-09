[CmdletBinding()]
param(
    [string]$Go = 'go',
    [string]$SdkRoot = $env:ANDROID_HOME,
    [string]$NdkVersion = '26.3.11579264'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $SdkRoot) { $SdkRoot = $env:ANDROID_SDK_ROOT }
$Go = (Get-Command $Go -ErrorAction Stop).Source
$clang = Join-Path $SdkRoot "ndk\$NdkVersion\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
if (-not (Test-Path -LiteralPath $clang)) { throw 'Android NDK clang was not found.' }
$variables = @('GOOS','GOARCH','CGO_ENABLED','CC','GOCACHE','GOTMPDIR','GOMODCACHE','GOTOOLCHAIN','TEMP','TMP')
$previous = @{}
foreach ($name in $variables) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:GOOS = 'android'; $env:CGO_ENABLED = '1'; $env:GOTOOLCHAIN = 'local'
    $env:GOCACHE = Join-Path $projectRoot '.build\go-cache'
    $env:GOTMPDIR = Join-Path $projectRoot '.build\go-temp'
    $env:GOMODCACHE = Join-Path $projectRoot '.build\go-mod-cache'
    $env:TEMP = $env:GOTMPDIR; $env:TMP = $env:GOTMPDIR
    foreach ($directory in @($env:GOCACHE,$env:GOTMPDIR,$env:GOMODCACHE)) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
    Push-Location $projectRoot
    try {
        foreach ($target in @(@{Abi='arm64-v8a';Arch='arm64';Triple='aarch64-linux-android29'},@{Abi='x86_64';Arch='amd64';Triple='x86_64-linux-android29'})) {
            $env:GOARCH = $target.Arch
            $env:CC = '"' + $clang.Replace('\','/') + '" --target=' + $target.Triple
            $destination = Join-Path $projectRoot ('.build\android-core\' + $target.Abi)
            New-Item -ItemType Directory -Force -Path $destination | Out-Null
            & $Go build -mod=readonly -buildmode=c-shared -trimpath -ldflags '-s -w -extldflags=-Wl,-z,max-page-size=16384' -o (Join-Path $destination 'libsucrune_core.so') ./cmd/sucrunecore
            if ($LASTEXITCODE -ne 0) { throw "Go Android core build failed: $($target.Abi)" }
            Write-Output "Go management core built: $($target.Abi)"
        }
    } finally { Pop-Location }
} finally {
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
