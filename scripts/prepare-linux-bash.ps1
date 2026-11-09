[CmdletBinding()]
param(
    [string]$CacheDirectory,
    [string]$OutputDirectory,
    [string]$ReadElf,
    [switch]$Offline
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $project '.build/linux-package-cache' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $project 'android/probeapp/src/androidTest/assets/linux-bash' }
if (-not $ReadElf -and $env:ANDROID_NDK_HOME) {
    $candidate = Get-ChildItem (Join-Path $env:ANDROID_NDK_HOME 'toolchains/llvm/prebuilt/*/bin/llvm-readelf*') -File |
        Select-Object -First 1
    if ($candidate) { $ReadElf = $candidate.FullName }
}
if (-not $ReadElf) { $ReadElf = (Get-Command llvm-readelf -CommandType Application -ErrorAction Stop).Source }
$tar = (Get-Command tar -CommandType Application -ErrorAction Stop).Source
$CacheDirectory = [IO.Path]::GetFullPath($CacheDirectory)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

function Assert-PlainPath([string]$Path) {
    for ($p = [IO.Path]::GetFullPath($Path); $p; $p = Split-Path -Parent $p) {
        if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Unexpected reparse point at $p"
        }
    }
}
function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function New-Package($Id, $Version, $Arch, $Pool, $Hash) {
    $name = "${Id}_${Version}_${Arch}.deb"
    [ordered]@{id=$Id; version=$Version; architecture=$Arch; name=$name; sha256=$Hash
        url="https://deb.debian.org/debian/pool/main/$Pool/$name"
        checksum_source="https://packages.debian.org/bookworm/$Arch/$Id/download"}
}
$packages = @(
    New-Package bash '5.2.15-2+b13' arm64 'b/bash' 'fdb470b5ec1773b90014138bfc1deda4505c1c23e7f5731e8b527c636ac03385'
    New-Package libtinfo6 '6.4-4' arm64 'n/ncurses' 'baef0f6776f84c7eed4f1146d6e5774689567dad43216894d41da02e6608e4b3'
    New-Package ncurses-base '6.4-4' all 'n/ncurses' 'bfd1d89f833c09a28b062ee916495cf69649ca2bf529532476c7b69d75d24909'
    New-Package base-files '12.4+deb12u15' arm64 'b/base-files' 'b1272fbdc197f7d5bd22c05b741a03840f8bec66ca68c8d797f567ff2c99d42d'
)
function New-Member($Package, $Path, $Mode = 420, $Target = $Path) {
    [ordered]@{package=$Package; path=$Path; mode=$Mode; member=".$Target"}
}
$members = @(
    New-Member bash '/bin/bash' 493
    New-Member libtinfo6 '/lib/aarch64-linux-gnu/libtinfo.so.6' 420 '/lib/aarch64-linux-gnu/libtinfo.so.6.4'
    foreach ($term in @('d/dumb','x/xterm','x/xterm-256color')) { New-Member ncurses-base "/lib/terminfo/$term" }
    foreach ($package in $packages) { New-Member $package.id "/usr/share/doc/$($package.id)/copyright" }
    foreach ($license in @('GPL-2','GPL-3','GFDL-1.3')) { New-Member base-files "/usr/share/common-licenses/$license" }
)

function Read-Elf([string]$File, [string[]]$Options) {
    $lines = & $ReadElf -W @Options $File
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect ELF $File" }
    $lines -join "`n"
}
function Test-Elf([string]$File, [string[]]$Needed, [string]$Interpreter, [string]$Soname) {
    $headers = Read-Elf $File @('-h','-l','-d','-V')
    foreach ($field in @('Class:\s+ELF64','Data:\s+2.s complement, little endian','Type:\s+DYN','Machine:\s+AArch64')) {
        if ($headers -notmatch $field) { throw "Unexpected ELF field in ${File}: $field" }
    }
    $actualNeeded = @([regex]::Matches($headers,'\(NEEDED\).*?\[([^\]]+)\]') | ForEach-Object { $_.Groups[1].Value })
    if (Compare-Object $Needed $actualNeeded) { throw "Unexpected DT_NEEDED in ${File}: $actualNeeded" }
    $actualInterp = [regex]::Match($headers,'Requesting program interpreter: ([^\]]+)').Groups[1].Value
    $actualSoname = [regex]::Match($headers,'\(SONAME\).*?\[([^\]]+)\]').Groups[1].Value
    if ($actualInterp -cne $Interpreter -or $actualSoname -cne $Soname) { throw "Unexpected interpreter or SONAME in $File" }
    $versions = @([regex]::Matches($headers,'Name: GLIBC_(\d+\.\d+(?:\.\d+)?)') |
        ForEach-Object { [version]$_.Groups[1].Value } | Sort-Object -Unique)
    if (-not $versions -or $versions[-1] -gt [version]'2.36') { throw "Incompatible glibc requirements in $File" }
    [ordered]@{machine='AArch64'; type='ET_DYN'; interpreter=$actualInterp; soname=$actualSoname
        needed=$actualNeeded; highest_glibc=$versions[-1].ToString()}
}
function Get-BashVersion([string]$File) {
    # Read Bash's exported version variables from this PIE without executing it.
    $symbols = Read-Elf $File @('--dyn-syms')
    $relocations = Read-Elf $File @('-r')
    $segments = [regex]::Matches((Read-Elf $File @('-l')),
        '(?m)^\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)')
    $bytes = [IO.File]::ReadAllBytes($File)
    $decoded = @{}
    foreach ($name in @('dist_version','patch_level','build_version','release_status')) {
        $symbol = [regex]::Match($symbols, "(?m)^\s*\d+: ([0-9a-f]+)\s+\d+ OBJECT\s+GLOBAL DEFAULT\s+\d+ $name`$")
        if (-not $symbol.Success) { throw "Missing Bash version symbol $name" }
        $hex = $symbol.Groups[1].Value
        $pointer = $name -in @('dist_version','release_status')
        if ($pointer) {
            $rel = [regex]::Match($relocations, "(?m)^$hex\s+[0-9a-f]+ R_AARCH64_RELATIVE\s+([0-9a-f]+)\s*`$")
            if (-not $rel.Success) { throw "Missing version string relocation for $name" }
            $hex = $rel.Groups[1].Value
        }
        $address = [Convert]::ToUInt64($hex,16)
        foreach ($segment in $segments) {
            $start = [Convert]::ToUInt64($segment.Groups[2].Value,16)
            $size = [Convert]::ToUInt64($segment.Groups[3].Value,16)
            if ($address -lt $start -or $address -ge $start + $size) { continue }
            $offset = [int]([Convert]::ToUInt64($segment.Groups[1].Value,16) + $address - $start)
            if ($pointer) {
                $nul = [Array]::IndexOf($bytes, [byte]0, $offset)
                if ($nul -lt $offset -or $nul -gt $offset+32) { throw "Invalid version string for $name" }
                $decoded[$name] = [Text.Encoding]::ASCII.GetString($bytes,$offset,$nul-$offset)
            } else { $decoded[$name] = [BitConverter]::ToInt32($bytes,$offset) }
            break
        }
        if (-not $decoded.ContainsKey($name)) { throw "Unmapped Bash version variable $name" }
    }
    '{0}.{1}({2})-{3}' -f $decoded.dist_version,$decoded.patch_level,$decoded.build_version,$decoded.release_status
}

Assert-PlainPath $CacheDirectory
Assert-PlainPath $OutputDirectory
$manifestPath = Join-Path $OutputDirectory 'manifest.json'
Assert-PlainPath $manifestPath
$hasManifest = Test-Path -LiteralPath $manifestPath
if ($hasManifest -and (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).name -cne 'debian-bookworm-arm64-bash') {
    throw 'Output contains a different fixture.'
}
if ((Test-Path -LiteralPath $OutputDirectory) -and -not $hasManifest) {
    # An interrupted first run may have published some of these exact assets.
    # Reject unrelated populated directories before writing anything.
    $known = @($members | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $OutputDirectory ('files'+$_.path))) })
    foreach ($entry in Get-ChildItem -LiteralPath $OutputDirectory -Force -Recurse) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            (-not $entry.PSIsContainer -and $entry.FullName -notin $known)) { throw "Unexpected output entry $($entry.FullName)" }
    }
}
$scratchParent = Join-Path $project '.build'
$scratch = Join-Path $scratchParent ('bash-extract-' + [guid]::NewGuid().ToString('N'))
Assert-PlainPath $scratch
New-Item -ItemType Directory -Force -Path $CacheDirectory,$scratch | Out-Null
try {
    foreach ($package in $packages) {
        $archive = Join-Path $CacheDirectory $package.name
        Assert-PlainPath $archive
        if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
            if ($Offline) { throw "Missing cached package $($package.name)" }
            $partial = Join-Path $CacheDirectory ($package.name + '.' + [guid]::NewGuid().ToString('N') + '.part')
            try {
                Invoke-WebRequest $package.url -OutFile $partial
                if ((Get-Sha256 $partial) -ne $package.sha256) { throw "Download checksum mismatch for $($package.id)" }
                [IO.File]::Move($partial,$archive)
            } finally { if ([IO.File]::Exists($partial)) { [IO.File]::Delete($partial) } }
        }
        if ((Get-Sha256 $archive) -ne $package.sha256) { throw "Cached checksum mismatch for $($package.id)" }
        $package.bytes = (Get-Item -LiteralPath $archive).Length
        $dir = Join-Path $scratch $package.id
        New-Item -ItemType Directory -Path $dir | Out-Null
        & $tar -xf $archive -C $dir 'data.tar.xz' 'control.tar.xz'
        if ($LASTEXITCODE) { throw "Cannot open package $($package.id)" }
        & $tar -xf (Join-Path $dir 'control.tar.xz') -C $dir './control'
        if ($LASTEXITCODE) { throw "Missing package control $($package.id)" }
        $metadata = Get-Content -LiteralPath (Join-Path $dir 'control')
        foreach ($field in @("Package: $($package.id)","Version: $($package.version)","Architecture: $($package.architecture)")) {
            if ($field -cnotin $metadata) { throw "Package metadata mismatch for $field" }
        }
        $names = @($members | Where-Object package -eq $package.id | ForEach-Object { $_.member })
        & $tar -xf (Join-Path $dir 'data.tar.xz') -C $dir @names
        if ($LASTEXITCODE) { throw "Cannot extract required regular files from $($package.id)" }
    }
    $bash = Join-Path $scratch 'bash/bin/bash'
    $tinfo = Join-Path $scratch 'libtinfo6/lib/aarch64-linux-gnu/libtinfo.so.6.4'
    $bashElf = Test-Elf $bash @('libtinfo.so.6','libc.so.6','ld-linux-aarch64.so.1') '/lib/ld-linux-aarch64.so.1' ''
    $tinfoElf = Test-Elf $tinfo @('libc.so.6','ld-linux-aarch64.so.1') '' 'libtinfo.so.6'
    $bashVersion = Get-BashVersion $bash
    if ($bashVersion -cne '5.2.15(1)-release') { throw "Unexpected Bash executable version $bashVersion" }
    $files = foreach ($member in $members) {
        $source = Join-Path (Join-Path $scratch $member.package) $member.member
        Assert-PlainPath $source
        $asset = 'files' + $member.path
        $target = Join-Path $OutputDirectory $asset
        Assert-PlainPath $target
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -Force
        $row = [ordered]@{path=$member.path; asset=$asset; mode=$member.mode; bytes=(Get-Item -LiteralPath $source).Length
            sha256=(Get-Sha256 $source); package=$member.package; archive_member=$member.member}
        if ($member.member -cne ('.' + $member.path)) { $row.materialized_link_target = $member.member.Substring(1) }
        if ((Get-Sha256 $target) -ne $row.sha256) { throw "Output checksum mismatch for $asset" }
        $row
    }
    $manifest = [ordered]@{schema_version=1; name='debian-bookworm-arm64-bash'; executable='/bin/bash'; bash_version=$bashVersion
        base_requires=@('/lib/ld-linux-aarch64.so.1','/lib/aarch64-linux-gnu/libc.so.6')
        terminfo=@('dumb','xterm','xterm-256color'); bash_elf=$bashElf; libtinfo_elf=$tinfoElf
        packages=$packages; files=@($files)}
    $newManifest = "$manifestPath.$([guid]::NewGuid().ToString('N')).part"
    try {
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $newManifest -Encoding utf8
        if ([IO.File]::Exists($manifestPath)) {
            [IO.File]::Replace($newManifest,$manifestPath,[System.Management.Automation.Language.NullString]::Value)
        }
        else { [IO.File]::Move($newManifest,$manifestPath) }
    } finally { if ([IO.File]::Exists($newManifest)) { [IO.File]::Delete($newManifest) } }
    Write-Output "Prepared $($files.Count) Bash fixture files ($bashVersion) in $OutputDirectory"
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    if ((Split-Path -Parent $resolved) -ne [IO.Path]::GetFullPath($scratchParent) -or
        (Split-Path -Leaf $resolved) -notmatch '^bash-extract-[0-9a-f]{32}$') { throw 'Invalid scratch cleanup path' }
    Assert-PlainPath $resolved
    if (@(Get-ChildItem -LiteralPath $resolved -Force -Recurse | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
        throw 'Unexpected link in scratch'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
