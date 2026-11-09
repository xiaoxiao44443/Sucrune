[CmdletBinding()]
param(
    [string]$CacheDirectory,
    [string]$OutputDirectory,
    [switch]$IncludeNode,
    [switch]$Offline
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $projectRoot '.build\linux-package-cache' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot 'android\probeapp\src\androidTest\assets\linux-rootfs' }
$CacheDirectory = [IO.Path]::GetFullPath($CacheDirectory)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$tarCommand = (Get-Command tar -CommandType Application -ErrorAction Stop).Source

function Assert-PlainPath([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "A rootfs path cannot traverse a reparse point: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}
Assert-PlainPath $CacheDirectory
Assert-PlainPath $OutputDirectory
New-Item -ItemType Directory -Force -Path $CacheDirectory, $OutputDirectory | Out-Null

$packages = @(
    @{id='hello';name='hello_2.10-3_arm64.deb';url='https://deb.debian.org/debian/pool/main/h/hello/hello_2.10-3_arm64.deb';sha256='f7b20d304db0f3a18da28eb2000de2b0205eaa340c1d0fecec3b7c50acc932dc';checksum_source='https://packages.debian.org/bookworm/arm64/hello/download'},
    @{id='libc6';name='libc6_2.36-9+deb12u14_arm64.deb';url='https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u14_arm64.deb';sha256='01f4330719fd4f65580e16ea5a0527f372fca750e8f588d26deaf09f2d3b1cf4';checksum_source='https://packages.debian.org/bookworm/arm64/libc6/download'},
    @{id='libc-bin';name='libc-bin_2.36-9+deb12u14_arm64.deb';url='https://deb.debian.org/debian/pool/main/g/glibc/libc-bin_2.36-9+deb12u14_arm64.deb';sha256='65166ea54c05213c4f48d889138179f1b7345edd05031a9af276aa5fb4a45c05';checksum_source='https://packages.debian.org/bookworm/arm64/libc-bin/download'},
    @{id='libstdc++6';name='libstdc++6_12.2.0-14+deb12u1_arm64.deb';url='https://deb.debian.org/debian/pool/main/g/gcc-12/libstdc++6_12.2.0-14+deb12u1_arm64.deb';sha256='26e138c677a985775331373828a6c286c551ff397cb735d00e2383cb273d1cb2';checksum_source='https://packages.debian.org/bookworm/arm64/libstdc++6/download'},
    @{id='libgcc-s1';name='libgcc-s1_12.2.0-14+deb12u1_arm64.deb';url='https://deb.debian.org/debian/pool/main/g/gcc-12/libgcc-s1_12.2.0-14+deb12u1_arm64.deb';sha256='576926b283613db80168ddf76380a3bd877602778cf0d226caa7bfbfa71eacf3';checksum_source='https://packages.debian.org/bookworm/arm64/libgcc-s1/download'},
    @{id='gcc-12-base';name='gcc-12-base_12.2.0-14+deb12u1_arm64.deb';url='https://deb.debian.org/debian/pool/main/g/gcc-12/gcc-12-base_12.2.0-14+deb12u1_arm64.deb';sha256='674cf6cba6d432bd200c45fe866c1652c7a53523cc2e7a613e05bc4abf7b5440';checksum_source='https://packages.debian.org/bookworm/arm64/gcc-12-base/download'}
)
if ($IncludeNode) {
    $packages += @{id='node';name='node-v24.22.2-linux-arm64.tar.xz';url='https://nodejs.org/download/release/v24.22.2/node-v24.22.2-linux-arm64.tar.xz';sha256='eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8';checksum_source='https://nodejs.org/download/release/v24.22.2/SHASUMS256.txt'}
}
$members = @(
    @{package='hello';member='./usr/bin/hello';path='/usr/bin/hello';mode=493},
    @{package='hello';member='./usr/share/doc/hello/copyright';path='/usr/share/doc/hello/copyright';mode=420},
    @{package='libc6';member='./lib/aarch64-linux-gnu/ld-linux-aarch64.so.1';path='/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1';mode=493},
    @{package='libc6';member='./lib/aarch64-linux-gnu/ld-linux-aarch64.so.1';path='/lib/ld-linux-aarch64.so.1';mode=493;materialized_link_target='/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'},
    @{package='libc6';member='./lib/aarch64-linux-gnu/libc.so.6';path='/lib/aarch64-linux-gnu/libc.so.6';mode=493},
    @{package='libc6';member='./lib/aarch64-linux-gnu/libdl.so.2';path='/lib/aarch64-linux-gnu/libdl.so.2';mode=420},
    @{package='libc6';member='./lib/aarch64-linux-gnu/libpthread.so.0';path='/lib/aarch64-linux-gnu/libpthread.so.0';mode=420},
    @{package='libc6';member='./lib/aarch64-linux-gnu/librt.so.1';path='/lib/aarch64-linux-gnu/librt.so.1';mode=420},
    @{package='libc6';member='./lib/aarch64-linux-gnu/libm.so.6';path='/lib/aarch64-linux-gnu/libm.so.6';mode=420},
    @{package='libc6';member='./usr/share/doc/libc6/copyright';path='/usr/share/doc/libc6/copyright';mode=420},
    @{package='libstdc++6';member='./usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.30';path='/usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.30';mode=420},
    @{package='libstdc++6';member='./usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.30';path='/usr/lib/aarch64-linux-gnu/libstdc++.so.6';mode=420;materialized_link_target='/usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.30'},
    @{package='libgcc-s1';member='./lib/aarch64-linux-gnu/libgcc_s.so.1';path='/lib/aarch64-linux-gnu/libgcc_s.so.1';mode=420},
    @{package='gcc-12-base';member='./usr/share/doc/gcc-12-base/copyright';path='/usr/share/doc/gcc-12-base/copyright';mode=420}
)
# Use the complete matching glibc C.utf8 locale, not an environment-only claim.
# These are regular data members; no localedef or package maintainer script runs.
foreach ($category in @('LC_ADDRESS','LC_COLLATE','LC_CTYPE','LC_IDENTIFICATION','LC_MEASUREMENT',
        'LC_MESSAGES/SYS_LC_MESSAGES','LC_MONETARY','LC_NAME','LC_NUMERIC','LC_PAPER','LC_TELEPHONE','LC_TIME')) {
    $path = '/usr/lib/locale/C.utf8/' + $category
    $members += @{package='libc-bin';member='.'+$path;path=$path;mode=420}
}
$members += @{package='libc-bin';member='./usr/share/doc/libc-bin/copyright';path='/usr/share/doc/libc-bin/copyright';mode=420}
if ($IncludeNode) {
    $members += @{package='node';member='node-v24.22.2-linux-arm64/bin/node';path='/usr/bin/node';mode=493}
    $members += @{package='node';member='node-v24.22.2-linux-arm64/LICENSE';path='/usr/share/doc/node/LICENSE';mode=420}
}
$manifestPath = Join-Path $OutputDirectory 'manifest.json'
if (Test-Path -LiteralPath $manifestPath) {
    $existing = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([bool]$existing.includes_node -ne [bool]$IncludeNode) {
        throw 'Existing output has a different Node profile. Choose a distinct OutputDirectory; this script never deletes old files.'
    }
}
$scratchParent = Join-Path $projectRoot '.build'
$scratch = Join-Path $scratchParent ('rootfs-extract-' + [guid]::NewGuid().ToString('N'))
Assert-PlainPath $scratch
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$manifestFiles = [Collections.Generic.List[object]]::new()
try {
    foreach ($package in $packages) {
        $archive = Join-Path $CacheDirectory $package.name
        Assert-PlainPath $archive
        if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
            if ($Offline) { throw "Missing offline package: $archive" }
            Invoke-WebRequest $package.url -OutFile $archive
        }
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $package.sha256) {
            throw "Package checksum mismatch: $($package.name)"
        }
        $package.bytes = (Get-Item -LiteralPath $archive).Length
        $directory = Join-Path $scratch $package.id
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
        $dataArchive = $archive
        if ($package.name.EndsWith('.deb')) {
            # Only extract the known data member; never install/run maintainer scripts.
            & $tarCommand -xf $archive -C $directory 'data.tar.xz'
            if ($LASTEXITCODE -ne 0) { throw "Cannot extract data member: $($package.name)" }
            $dataArchive = Join-Path $directory 'data.tar.xz'
        }
        $wanted = @($members | Where-Object { $_.package -eq $package.id })
        $names = @($wanted | ForEach-Object { $_.member } | Select-Object -Unique)
        & $tarCommand -xf $dataArchive -C $directory @names
        if ($LASTEXITCODE -ne 0) { throw "Cannot extract verified regular files: $($package.name)" }
        foreach ($member in $wanted) {
            $source = Join-Path $directory $member.member
            Assert-PlainPath $source
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing member: $($member.member)" }
            $relative = 'files' + $member.path
            $target = [IO.Path]::GetFullPath((Join-Path $OutputDirectory $relative))
            if (-not $target.StartsWith($OutputDirectory.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Escaping rootfs member: $relative"
            }
            Assert-PlainPath $target
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
            Copy-Item -LiteralPath $source -Destination $target -Force
            $row = [ordered]@{path=$member.path;asset=$relative;mode=$member.mode;bytes=(Get-Item -LiteralPath $target).Length;sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash;package=$package.id;archive_member=$member.member}
            if ($member.ContainsKey('materialized_link_target')) { $row.materialized_link_target = $member.materialized_link_target }
            $manifestFiles.Add($row)
        }
    }
    [ordered]@{
        schema_version=1; name='debian-bookworm-arm64-node24-candidate'; includes_node=[bool]$IncludeNode
        role='Verified upstream dynamic ELF test inputs; not a complete distribution or a successful runtime test.'
        architectures=@('aarch64'); loader='/lib/ld-linux-aarch64.so.1'; hello='/usr/bin/hello'
        recommended_environment=@('LC_ALL=C.UTF-8','LANG=C.UTF-8','LD_LIBRARY_PATH=/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu')
        locale='C.UTF-8'; locale_data='/usr/lib/locale/C.utf8'
        link_policy='Listed symlink targets are deliberately materialized as identical regular-file bytes; no archive symlinks are extracted.'
        source_policy='Pinned HTTPS package hashes checked; release-signature validation is not claimed. Archive scripts are never executed.'
        packages=$packages; files=@($manifestFiles)
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    Write-Output "Prepared $($manifestFiles.Count) verified regular files: $manifestPath"
} finally {
    $resolved = [IO.Path]::GetFullPath($scratch)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath($scratchParent).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside the exact build scratch parent.'
    }
    Assert-PlainPath $resolved
    if (@(Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -ne 0) {
        throw 'Unexpected reparse point in extraction scratch; refusing recursive cleanup.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
