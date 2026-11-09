[CmdletBinding()]
param(
    [ValidateSet('CliSmoke','SdkMinimal','Full')][string]$Profile='CliSmoke',
    [string]$Provenance, [string]$CacheDirectory, [string]$OutputDirectory,
    [switch]$ManifestOnly, [switch]$Offline, [switch]$Bundle, [switch]$BundleOnly
)
# Pure offline preparation. No npm, package scripts, host CLI, or network.
# Requires PowerShell 7.4+, Windows bsdtar, and the pinned tar cache.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $Provenance) { $Provenance=Join-Path $projectRoot 'docs/dsh-rootfs-provenance.json' }
if (-not $CacheDirectory) { $CacheDirectory=Join-Path $projectRoot '.build/dsh-tarballs' }
if (-not $OutputDirectory) {
    $suffix=switch ($Profile) { 'CliSmoke' { 'smoke' }; 'SdkMinimal' { 'sdk-minimal' }; 'Full' { 'full' } }
    if ($ManifestOnly) { $suffix+='-index' }
    $OutputDirectory=Join-Path $projectRoot ('.build/dsh-rootfs-'+$suffix)
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
function Assert-PlainPath([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Reparse path rejected: $cursor" }
        $parent=Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }; $cursor=$parent
    }
}
function Assert-Relative([string]$Path) {
    if (-not $Path -or $Path.Contains('\') -or $Path.StartsWith('/') -or $Path.Contains([char]0)) { throw "Invalid package path: $Path" }
    foreach ($part in $Path.Split('/')) { if (-not $part -or $part -eq '.' -or $part -eq '..') { throw "Invalid package segment: $Path" } }
}
function Write-RootfsBundle([object]$Manifest) {
    if (-not $Manifest.assets_materialized) { throw 'Bundle requires materialized verified assets.' }
    Assert-PlainPath (Join-Path $OutputDirectory 'files')
    $bundlePath=Join-Path $OutputDirectory 'rootfs.bundle.gz'
    $receiptPath=Join-Path $OutputDirectory 'bundle.json'
    if ((Test-Path -LiteralPath $bundlePath) -or (Test-Path -LiteralPath $receiptPath)) { throw 'Bundle output already exists.' }
    $records=@($Manifest.files | ForEach-Object { [ordered]@{path=$_.path;mode=$_.mode;bytes=$_.bytes;sha256=$_.sha256} })
    $index=[ordered]@{schema_version=1;format='sucrune-file-bundle-v1';name=$Manifest.name;guest_prefix='/opt/dsh';file_count=$records.Count;total_bytes=$Manifest.total_bytes;package_count=$Manifest.package_count;source_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant();files=$records}
    $json=[Text.Encoding]::UTF8.GetBytes(($index | ConvertTo-Json -Depth 8 -Compress))
    if ($json.Length -gt 16MB -or $records.Count -gt 100000 -or $Manifest.total_bytes -gt 2GB) { throw 'Bundle index or payload exceeds installer bounds.' }
    $indexSha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($json)).ToLowerInvariant()
    $magic=[Text.Encoding]::ASCII.GetBytes("SUCRUNE-BUNDLE-1`n")
    $length=[BitConverter]::GetBytes([uint32]$json.Length)
    if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }
    $temporary=Join-Path $OutputDirectory ('.pending-bundle-'+[guid]::NewGuid().ToString('N'))
    $file=$null; $gzip=$null; $copyBuffer=[byte[]]::new(65536); $copied=[long]0
    try {
        $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $gzip=[IO.Compression.GZipStream]::new($file,[IO.Compression.CompressionLevel]::Optimal,$true)
        $gzip.Write($magic,0,$magic.Length); $gzip.Write($length,0,$length.Length); $gzip.Write($json,0,$json.Length)
        foreach ($row in $Manifest.files) {
            if (-not $row.path.StartsWith('/opt/dsh/') -or $row.sha256 -notmatch '^[0-9a-f]{64}$' -or $row.asset -ne ('files/'+$row.sha256+'.bin') -or $row.bytes -lt 0 -or $row.bytes -gt 256MB -or $row.mode -lt 0 -or $row.mode -gt 511) { throw 'Invalid verified bundle row.' }
            Assert-Relative $row.path.Substring(1)
            $blob=Join-Path $OutputDirectory $row.asset
            # Asset names contain only a validated hash and have no subfolders.
            # The common parent chain was checked once above; reject link leaves.
            if ([IO.File]::GetAttributes($blob) -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) { throw 'Bundle asset is not a plain regular file.' }
            $input=$null; $digest=[Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
            try {
                $input=[IO.File]::OpenRead($blob)
                if ($input.Length -ne $row.bytes) { throw 'Bundle asset length changed.' }
                while (($count=$input.Read($copyBuffer,0,$copyBuffer.Length)) -gt 0) {
                    $digest.AppendData($copyBuffer,0,$count); $gzip.Write($copyBuffer,0,$count); $copied+=$count
                }
                if ([Convert]::ToHexString($digest.GetHashAndReset()).ToLowerInvariant() -ne $row.sha256) { throw 'Bundle asset SHA256 changed.' }
            } finally { if ($null -ne $input) { $input.Dispose() }; $digest.Dispose() }
        }
        if ($copied -ne $Manifest.total_bytes -or $records.Count -ne $Manifest.file_count) { throw 'Bundle totals disagree.' }
        $gzip.Dispose(); $gzip=$null; $file.Flush($true); $file.Dispose(); $file=$null
        $bytes=(Get-Item -LiteralPath $temporary).Length
        if ($bytes -gt 256MB) { throw 'Compressed bundle exceeds streaming import limit.' }
        $sha=(Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::Move($temporary,$bundlePath)
        [ordered]@{schema_version=1;format='sucrune-file-bundle-v1';asset='rootfs.bundle.gz';bytes=$bytes;sha256=$sha;compression='gzip';decompressed_magic="SUCRUNE-BUNDLE-1`n";magic_bytes=$magic.Length;index_length='uint32 little endian immediately after magic';index_bytes=$json.Length;index_sha256=$indexSha;payload='UTF-8 JSON index then consecutive raw file bytes in index.files order; require exact stream EOF after final file';decompressed_bytes=($magic.Length+4+$json.Length+$copied);file_count=$records.Count;package_count=$Manifest.package_count;source_manifest_sha256=$index.source_manifest_sha256;security='Validate all paths and size bounds; publish only complete regular files after matching SHA256; set only 0600/0700 import modes; never follow links.'} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $receiptPath -Encoding utf8
        Write-Output "Bundled $($records.Count) files: $bytes compressed bytes, SHA256 $sha"
        Write-Output $bundlePath
    } finally {
        if ($null -ne $gzip) { $gzip.Dispose() }; if ($null -ne $file) { $file.Dispose() }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}
Assert-PlainPath $Provenance
Assert-PlainPath $CacheDirectory
Assert-PlainPath $OutputDirectory
$pin=Get-Content -LiteralPath $Provenance -Raw | ConvertFrom-Json -AsHashtable
$expected='sha512-ijR9UEVYkG15Q/Q79JzvzLBzQOQfc63VLr9n6flpwHPhr5IKn2UxthnSoto/P9l7qGd7pPvI1Ra6TW7LH3oKpg=='
if ($pin.schema_version -ne 1 -or $pin.version -ne '0.2.2-rc.1' -or $pin.guest_prefix -ne '/opt/dsh' -or $pin.top_level_integrity -ne $expected -or $pin.npm_lockfile.packages['node_modules/@deepseek-ai/dsh'].integrity -ne $expected) { throw 'Invalid pinned DSH provenance.' }
if ($ManifestOnly -and ($Bundle -or $BundleOnly)) { throw 'ManifestOnly cannot produce a bundle.' }
if ($BundleOnly) {
    $manifestPath=Join-Path $OutputDirectory 'manifest.json'; Assert-PlainPath $manifestPath
    $existing=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if (-not $existing.name.StartsWith('official-dsh-0.2.2-rc.1-') -or $existing.source_provenance_sha256 -ne (Get-FileHash -LiteralPath $Provenance -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Bundle manifest does not match pinned provenance.' }
    Write-RootfsBundle $existing
    return
}
$profileSeeds=@('node_modules/@deepseek-ai/dsh-sdk-minimal','node_modules/@deepseek-ai/dsh-http-proxy','node_modules/@deepseek-ai/dsh-cmdline')
function Resolve-LockedDependency([string]$From,[string]$Name) {
    Assert-Relative $Name
    $cursor=$From
    while ($true) {
        if ($cursor -ne 'node_modules' -and -not $cursor.EndsWith('/node_modules')) {
            $candidate=if ($cursor) { $cursor+'/node_modules/'+$Name } else { 'node_modules/'+$Name }
            if ($pin.npm_lockfile.packages.Contains($candidate)) { return $candidate }
        }
        if (-not $cursor) { return $null }
        $slash=$cursor.LastIndexOf('/')
        $cursor=if ($slash -lt 0) { '' } else { $cursor.Substring(0,$slash) }
    }
}
if ($Profile -eq 'SdkMinimal') {
    # The unmodified public CLI is retained, but only its selected boot path is
    # expanded. Root dsh also declares unrelated Web/ACP/optional bundles. The
    # profile-boot chunk additionally imports http-proxy and cmdline. All deps,
    # peers and selected ARM64 GNU optionals of these seeds are then complete.
    $selected=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pendingPackages=[Collections.Generic.Queue[string]]::new()
    foreach ($seed in @($pin.cli_smoke_package_paths)+$profileSeeds) {
        if ($seed -notin $pin.selected_package_paths) { throw "Unpinned profile seed: $seed" }
        if ($selected.Add($seed)) { $pendingPackages.Enqueue($seed) }
    }
    while ($pendingPackages.Count -gt 0) {
        $current=$pendingPackages.Dequeue()
        if ($current -eq 'node_modules/@deepseek-ai/dsh') { continue }
        $locked=$pin.npm_lockfile.packages[$current]
        foreach ($section in @('dependencies','peerDependencies','optionalDependencies')) {
            if (-not $locked.Contains($section)) { continue }
            foreach ($name in $locked[$section].Keys) {
                $dependency=Resolve-LockedDependency $current $name
                $optional=$section -eq 'optionalDependencies' -or ($locked.Contains('optionalDependencies') -and $locked.optionalDependencies.Contains($name)) -or ($section -eq 'peerDependencies' -and $locked.Contains('peerDependenciesMeta') -and $locked.peerDependenciesMeta.Contains($name) -and $locked.peerDependenciesMeta[$name].Contains('optional') -and $locked.peerDependenciesMeta[$name].optional)
                if (-not $dependency -or $dependency -notin $pin.selected_package_paths) {
                    if ($optional) { continue }
                    throw "Missing required locked dependency: $current -> $name ($section)"
                }
                if ($selected.Add($dependency)) { $pendingPackages.Enqueue($dependency) }
            }
        }
    }
    $packagePaths=@($selected | Sort-Object)
} else { $packagePaths=if ($Profile -eq 'CliSmoke') { @($pin.cli_smoke_package_paths) } else { @($pin.selected_package_paths) } }
if ((Test-Path -LiteralPath $OutputDirectory) -and @(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -ne 0) { throw 'Output must be new or empty; old outputs are not removed.' }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
if (-not $ManifestOnly) { [void][IO.Directory]::CreateDirectory((Join-Path $OutputDirectory 'files')) }
$rows=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$packages=[Collections.Generic.List[object]]::new()
$buffer=[byte[]]::new(65536)
$totalBytes=[long]0
$tarProgram=(Get-Command tar -CommandType Application -ErrorAction Stop).Source
foreach ($packagePath in $packagePaths) {
    Assert-Relative $packagePath
    if (-not $packagePath.StartsWith('node_modules/') -or $packagePath -notin $pin.selected_package_paths -or -not $pin.npm_lockfile.packages.Contains($packagePath)) { throw "Unpinned package: $packagePath" }
    $package=$pin.npm_lockfile.packages[$packagePath]
    if ($package.integrity -notmatch '^sha512-([A-Za-z0-9+/]{86}==)$') { throw 'Expected SHA512 SRI.' }
    $hex=[Convert]::ToHexString([Convert]::FromBase64String($Matches[1])).ToLowerInvariant()
    $uri=[Uri]$package.resolved
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'registry.npmjs.org' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'Non-official npm tar source.' }
    $archive=Join-Path $CacheDirectory ($hex+'.tgz')
    Assert-PlainPath $archive
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw "Missing pinned archive; restore from $($package.resolved) and verify $($package.integrity)" }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA512).Hash.ToLowerInvariant() -ne $hex) { throw "Archive integrity mismatch: $packagePath" }
    $packages.Add([ordered]@{id=$packagePath;version=$package.version;url=$package.resolved;integrity=$package.integrity;bytes=(Get-Item -LiteralPath $archive).Length})
    # Some old npm GNU/PAX archives use base-256 UID/GID fields which overflow
    # .NET TarReader. Repack headers only, without filesystem extraction: owner
    # IDs are irrelevant to app-owned imports. Paths, file bytes and modes stay
    # intact, and the original tarball remains SHA512-verified and unchanged.
    $normalized=Join-Path $OutputDirectory ('.pending-archive-'+[guid]::NewGuid().ToString('N')+'.tar')
    & $tarProgram -cf $normalized --format pax --uid 0 --gid 0 ('@'+[IO.Path]::GetFullPath($archive))
    if ($LASTEXITCODE -ne 0) { if ([IO.File]::Exists($normalized)) { [IO.File]::Delete($normalized) }; throw "Cannot normalize tar ownership: $packagePath" }
    $stream=[IO.File]::OpenRead($normalized)
    $reader=[System.Formats.Tar.TarReader]::new($stream)
    $archiveRoot=$null
    try {
        while ($null -ne ($entry=$reader.GetNextEntry())) {
            $type=$entry.EntryType.ToString()
            if ($type -in @('Directory','GlobalExtendedAttributes','ExtendedAttributes')) { continue }
            if ($type -notin @('RegularFile','V7RegularFile')) { throw "Unsupported archive type $type; links/special files are not followed." }
            # Old npm archives can use the package name instead of 'package'.
            # Require one consistent, validated top directory and strip only it.
            # npm pack can preserve innocuous './' components (agent-base).
            # Remove only '.'; traversal, empty segments and rooted paths still
            # fail validation before a guest path or host file is constructed.
            if (-not $entry.Name -or $entry.Name.Contains('\') -or $entry.Name.StartsWith('/') -or $entry.Name.Contains([char]0)) { throw 'Invalid tar member path.' }
            $parts=@($entry.Name.Split('/') | Where-Object { $_ -ne '.' })
            $member=$parts -join '/'; Assert-Relative $member
            $slash=$member.IndexOf('/')
            if ($slash -le 0) { throw "Missing tar root directory: $($entry.Name)" }
            $root=$member.Substring(0,$slash)
            if ($null -eq $archiveRoot) { $archiveRoot=$root }
            elseif ($archiveRoot -ne $root) { throw 'Multiple roots in pinned npm archive.' }
            $relative=$member.Substring($slash+1); Assert-Relative $relative
            if ($entry.Length -lt 0 -or $entry.Length -gt 256MB) { throw 'File exceeds streaming import size.' }
            $guestPath='/opt/dsh/'+$packagePath+'/'+$relative
            if ([Text.Encoding]::UTF8.GetByteCount($guestPath) -ge 1024) { throw 'Guest path exceeds runtime limit.' }
            $pending=$null; $output=$null
            $hash=[Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
            try {
                if (-not $ManifestOnly) {
                    $pending=Join-Path $OutputDirectory ('.pending-'+[guid]::NewGuid().ToString('N'))
                    $output=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                }
                $count=[long]0
                while ($count -lt $entry.Length) {
                    $read=$entry.DataStream.Read($buffer,0,[int][Math]::Min($buffer.Length,$entry.Length-$count))
                    if ($read -le 0) { throw "Truncated tar entry: $guestPath" }
                    $hash.AppendData($buffer,0,$read)
                    if ($null -ne $output) { $output.Write($buffer,0,$read) }
                    $count+=$read
                }
                $sha256=[Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
                if ($null -ne $output) { $output.Flush($true); $output.Dispose(); $output=$null }
                $asset='files/'+$sha256+'.bin'
                if (-not $ManifestOnly) {
                    $blob=Join-Path $OutputDirectory $asset
                    if ([IO.File]::Exists($blob)) {
                        if ((Get-Item -LiteralPath $blob).Length -ne $count -or (Get-FileHash -LiteralPath $blob -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sha256) { throw 'Conflicting content-addressed asset.' }
                        [IO.File]::Delete($pending)
                    } else { [IO.File]::Move($pending,$blob) }
                    $pending=$null
                }
                $mode=[int]$entry.Mode -band 511
                $row=[ordered]@{path=$guestPath;asset=$asset;mode=$mode;bytes=$count;sha256=$sha256;package=$packagePath;archive_member=$entry.Name}
                if ($rows.ContainsKey($guestPath)) {
                    if ($rows[$guestPath].sha256 -ne $sha256 -or $rows[$guestPath].mode -ne $mode) { throw "Conflicting duplicate path: $guestPath" }
                } else { $rows.Add($guestPath,$row); $totalBytes+=$count }
                if ($rows.Count -gt 150000 -or $totalBytes -gt 2GB) { throw 'Preparation size bound exceeded.' }
            } finally {
                $hash.Dispose()
                if ($null -ne $output) { $output.Dispose() }
                if ($pending -and [IO.File]::Exists($pending)) { [IO.File]::Delete($pending) }
            }
        }
    } catch { throw "Cannot read pinned archive $packagePath ($($package.version)): $($_.Exception.Message)" }
    finally { $reader.Dispose(); $stream.Dispose(); [IO.File]::Delete($normalized) }
}
$entrypoint='/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js'
if (-not $rows.ContainsKey($entrypoint) -or $rows[$entrypoint].sha256 -ne $pin.cli_smoke.top_level_bin_sha256) { throw 'Public CLI entrypoint absent or changed.' }
$native='/opt/dsh/node_modules/node-addon-require-builtin-linux-arm64-gnu/prebuilt/linux-arm64-gnu-napi-v9.node'
if (-not $rows.ContainsKey($native)) { throw 'Required official ARM64 GNU native addon absent.' }
$manifest=[ordered]@{
    schema_version=1;name=('official-dsh-0.2.2-rc.1-'+$Profile.ToLowerInvariant());architectures=@('aarch64')
    role=switch ($Profile) { 'CliSmoke' { 'Unmodified official CLI version/help closure only; not full profiles or runtime success.' }; 'SdkMinimal' { 'Unmodified official sdk-minimal profile boot closure; every selected package is complete. Not full Web/Agent success.' }; 'Full' { 'Complete pinned Linux ARM64 glibc inputs; not runtime success.' } }
    assets_materialized=(-not $ManifestOnly);guest_prefix='/opt/dsh';entrypoint=$entrypoint
    recommended_argv=if ($Profile -eq 'SdkMinimal') { @('/usr/bin/node',$entrypoint,'sdk-minimal') } else { @('/usr/bin/node',$entrypoint,'--version') };alternate_argv=@('/usr/bin/node',$entrypoint,'--help')
    recommended_environment=@('HOME=/workspace/dsh-test-home','DSH_HOME=/workspace/dsh-test-home/.dsh','NARB_NATIVE_CACHE_DIR=/workspace/dsh-native-cache','DSH_TELEMETRY_DISABLED=1','TMPDIR=/workspace/dsh-tmp','LC_ALL=C.UTF-8','LANG=C.UTF-8','LD_LIBRARY_PATH=/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu')
    memory_policy='linux-jit';package_scripts_executed=$false;bin_links_created=$false
    source_policy=$pin.verification_policy;source_provenance_sha256=(Get-FileHash -LiteralPath $Provenance -Algorithm SHA256).Hash.ToLowerInvariant()
    asset_policy='Regular tar bytes addressed by SHA256 to preserve Linux paths on Windows. bsdtar normalizes only unused UID/GID headers for TarReader. No JS patches or host npm shims. Import executable=(mode & 0111)!=0.'
    excluded_package_paths=@($pin.selected_package_paths | Where-Object { $_ -notin $packagePaths })
    profile_closure=if ($Profile -eq 'SdkMinimal') { [ordered]@{seeds=$profileSeeds;retained_cli_seeds=@($pin.cli_smoke_package_paths);recursive_sections=@('dependencies','peerDependencies','optionalDependencies');installation_root_not_expanded='node_modules/@deepseek-ai/dsh';omitted_payload_files=0;stdin='Empty finite stream; EOF shutdown waits for official appReady.';expected_exit=0;not_claimed=@('npm install ran on Android','Web profile','Agent tool execution','model request')} } else { $null }
    install_script_review=$pin.install_script_review;incomplete_fixture_error_policy=$pin.cli_smoke.missing_dependency_classification
    total_bytes=$totalBytes;package_count=$packages.Count;file_count=$rows.Count
    packages=@($packages);files=@($rows.Values | Sort-Object { $_.path })
}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8
Write-Output "Prepared $Profile`: $($packages.Count) packages, $($rows.Count) files, $totalBytes bytes; materialized=$(-not $ManifestOnly)"
Write-Output (Join-Path $OutputDirectory 'manifest.json')
if ($Bundle) { Write-RootfsBundle $manifest }
