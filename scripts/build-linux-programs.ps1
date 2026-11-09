[CmdletBinding()]
param([string]$Zig = 'zig')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$Zig = (Get-Command $Zig -ErrorAction Stop).Source
$zigVersion = (& $Zig version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $zigVersion -ne '0.17.1') {
    throw 'Trusted Linux programs require Zig 0.17.1. Pass -Zig with its executable path; see native/programs/README.md.'
}
$outputDirectory = Join-Path $projectRoot '.build\linux-programs'
$variables = @('ZIG_GLOBAL_CACHE_DIR','ZIG_LOCAL_CACHE_DIR','TEMP','TMP')
$previous = @{}
foreach ($name in $variables) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

function Read-ProgramElf([string]$Path, [bool]$RequireTls) {
    # Validate emitted bytes, rather than merely the requested compiler flags.
    $elf = [IO.File]::ReadAllBytes($Path)
    if ($elf.Length -lt 64 -or $elf[0] -ne 127 -or $elf[1] -ne 69 -or $elf[2] -ne 76 -or $elf[3] -ne 70 -or $elf[4] -ne 2 -or $elf[5] -ne 1) {
        throw 'Linux program must be a little-endian ELF64 file.'
    }
    if ([BitConverter]::ToUInt16($elf,16) -ne 2 -or [BitConverter]::ToUInt16($elf,18) -ne 183) {
        throw 'Linux program must be an AArch64 ET_EXEC executable.'
    }
    $phoff = [BitConverter]::ToUInt64($elf,32)
    $phentsize = [BitConverter]::ToUInt16($elf,54)
    $phnum = [BitConverter]::ToUInt16($elf,56)
    if ($phentsize -ne 56 -or $phnum -eq 0 -or $phoff -gt [uint64]$elf.Length -or [uint64]$phentsize * $phnum -gt [uint64]$elf.Length - $phoff) {
        throw 'Linux program has an invalid program-header table.'
    }
    $headers = @()
    $loadCount = 0
    $tlsCount = 0
    for ($index = 0; $index -lt $phnum; $index++) {
        $offset = [int]($phoff + [uint64]$index * $phentsize)
        $type = [BitConverter]::ToUInt32($elf,$offset)
        $flags = [BitConverter]::ToUInt32($elf,$offset+4)
        $address = [BitConverter]::ToUInt64($elf,$offset+16)
        $alignment = [BitConverter]::ToUInt64($elf,$offset+48)
        if ($type -eq 2 -or $type -eq 3) { throw 'Linux program unexpectedly requires dynamic loading.' }
        if ($type -eq 1) {
            if ($alignment -ne 16384 -or ($flags -band 3) -eq 3) { throw 'Linux LOAD alignment or W^X policy is invalid.' }
            if ($loadCount -eq 0 -and $address -ne 0x20000000) { throw 'Linux image base is not 0x20000000.' }
            $loadCount++
        }
        if ($type -eq 7) { $tlsCount++ }
        if ($type -eq 0x6474e551 -and ($flags -band 1) -ne 0) { throw 'Linux program requests an executable stack.' }
        $headers += [ordered]@{
            type=$type; flags=$flags; offset=[BitConverter]::ToUInt64($elf,$offset+8)
            vaddr=$address; filesz=[BitConverter]::ToUInt64($elf,$offset+32)
            memsz=[BitConverter]::ToUInt64($elf,$offset+40); align=$alignment
        }
    }
    if ($loadCount -lt 2 -or $tlsCount -gt 1 -or ($RequireTls -and $tlsCount -ne 1)) {
        throw 'Linux program LOAD segments or TLS template count are invalid.'
    }
    return [ordered]@{bytes=$elf.Length;entry=[BitConverter]::ToUInt64($elf,24);tls_templates=$tlsCount;headers=$headers}
}

try {
    $env:ZIG_GLOBAL_CACHE_DIR = Join-Path $projectRoot '.build\zig-global-cache'
    $env:ZIG_LOCAL_CACHE_DIR = Join-Path $projectRoot '.build\zig-local-cache'
    $env:TEMP = Join-Path $projectRoot '.build\temp'
    $env:TMP = $env:TEMP
    foreach ($directory in @($outputDirectory,$env:ZIG_GLOBAL_CACHE_DIR,$env:ZIG_LOCAL_CACHE_DIR,$env:TEMP)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    $luaRoot = Join-Path $projectRoot 'third_party\lua'
    $luaProvenance = Get-Content -LiteralPath (Join-Path $luaRoot 'SOURCE.json') -Raw | ConvertFrom-Json
    if ($luaProvenance.version -ne '5.4.9' -or $luaProvenance.archive_sha256 -ne '2335B6C582A52654F94612BF10D2F4672805D05329AA6568B1D8CD9E5C6FB8E6') {
        throw 'Unexpected Lua source provenance.'
    }
    foreach ($file in $luaProvenance.files) {
        if ((Get-FileHash -LiteralPath (Join-Path $luaRoot $file.path) -Algorithm SHA256).Hash -ne $file.sha256) {
            throw "Vendored Lua file differs from the verified release: $($file.path)"
        }
    }
    $luaSources = @(Get-ChildItem -LiteralPath (Join-Path $luaRoot 'src') -File -Filter '*.c' |
        Where-Object Name -ne 'luac.c' | Sort-Object Name | ForEach-Object FullName)
    if ($luaSources.Count -ne 33) { throw 'Unexpected Lua interpreter source file count.' }
    $programs = @(
        [ordered]@{id='musl-smoke';version='fixture';artifact='sucrune-musl-smoke.elf';require_tls=$true;
            sources=@((Join-Path $projectRoot 'native\programs\musl_smoke.c'));flags=@()},
        [ordered]@{id='lua';version='5.4.9';artifact='sucrune-lua.elf';require_tls=$false;
            sources=$luaSources;flags=@('-DLUA_USE_POSIX');libraries=@('-lm')},
        [ordered]@{id='linux-landlock';version='fixture';artifact='linux-landlock.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\programs\linux_landlock.c'));flags=@()},
        [ordered]@{id='linux-signal-smoke';version='fixture';artifact='linux-signal-smoke.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\programs\linux_signal_smoke.c'));flags=@()},
        [ordered]@{id='linux-thread-smoke';version='fixture';artifact='linux-thread-smoke.elf';require_tls=$true;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\programs\linux_thread_smoke.c'));flags=@('-pthread')},
        [ordered]@{id='linux-io-smoke';version='fixture';artifact='linux-io-smoke.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\programs\linux_io_smoke.c'));flags=@('-pthread')},
        [ordered]@{id='linux-fork-continuation';version='fixture';artifact='linux-fork-continuation.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\guest\fork_continuation.S'));flags=@('-nostdlib','-Wl,-e,_start')},
        [ordered]@{id='linux-vfork-semantics';version='fixture';artifact='linux-vfork-semantics.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\guest\vfork_semantics.S'));flags=@('-nostdlib','-Wl,-e,_start')},
        [ordered]@{id='linux-fork-broker';version='fixture';artifact='linux-fork-broker.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\guest\fork_broker.c'));flags=@('-nostdlib','-Wl,-e,_start')},
        [ordered]@{id='linux-fork-exec';version='fixture';artifact='linux-fork-exec.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\guest\fork_exec.S'));flags=@('-nostdlib','-Wl,-e,_start')},
        [ordered]@{id='linux-pselect-smoke';version='fixture';artifact='linux-pselect-smoke.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\programs\linux_pselect_smoke.c'));flags=@()},
        [ordered]@{id='linux-fork-wait-states';version='fixture';artifact='linux-fork-wait-states.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\guest\fork_wait_states.c'));flags=@('-nostdlib','-Wl,-e,_start')},
        [ordered]@{id='linux-fork-stop-lease';version='fixture';artifact='linux-fork-stop-lease.elf';require_tls=$false;test_only=$true;
            sources=@((Join-Path $projectRoot 'native\guest\fork_stop_lease.c'));flags=@('-nostdlib','-Wl,-e,_start')}
    )
    $manifests = @()
    foreach ($program in $programs) {
        $outputPath = Join-Path $outputDirectory $program.artifact
        $arguments = @('cc','-target','aarch64-linux-musl','-O2','-std=c11','-Wall','-Wextra','-Werror',
            '-static','-fno-pie','-no-pie','-fno-stack-protector','-s',
            '-Wl,--image-base=0x20000000,-z,max-page-size=16384,--build-id=none')
        $arguments += $program.flags
        $arguments += $program.sources
        if ($program.Contains('libraries')) { $arguments += $program.libraries }
        $arguments += @('-o',$outputPath)
        & $Zig @arguments
        if ($LASTEXITCODE -ne 0) { throw "Linux program $($program.id) build failed with exit code $LASTEXITCODE." }
        $layout = Read-ProgramElf -Path $outputPath -RequireTls $program.require_tls
        $sourceHashes = @($program.sources | ForEach-Object {
            [ordered]@{file=[IO.Path]::GetRelativePath($projectRoot,$_).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
        })
        $entry = [ordered]@{
            program=$program.id; version=$program.version; target='aarch64-linux-musl'; compiler_version=$zigVersion
            source_sha256=$sourceHashes[0].sha256; sources=$sourceHashes
            artifact=$program.artifact; sha256=(Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
            bytes=$layout.bytes;elf_type='ET_EXEC';entry=$layout.entry;image_base=0x20000000
            dynamic_interpreter=$false;tls_templates=$layout.tls_templates;program_headers=$layout.headers
            build_options=@('aarch64-linux-musl','-O2','-static','-fno-pie','-no-pie','-fno-stack-protector','-s','--image-base=0x20000000','-z,max-page-size=16384') + $program.flags
        }
        if ($program.id -eq 'lua') {
            $entry.upstream_archive_sha256=$luaProvenance.archive_sha256
            $entry.upstream_sources_unmodified=$true
            $entry.dynamic_lua_modules=$false
        }
        if ($program.Contains('test_only')) {
            $testAssets = Join-Path $projectRoot '.build\linux-test-assets\linux-fixtures'
            New-Item -ItemType Directory -Force -Path $testAssets | Out-Null
            Copy-Item -LiteralPath $outputPath -Destination (Join-Path $testAssets $program.artifact) -Force
            [IO.File]::WriteAllText((Join-Path $testAssets ($program.id + '.json')), ($entry | ConvertTo-Json -Depth 10) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        } else { $manifests += $entry }
        Write-Output "Trusted ARM64 Linux program built and ELF verified: $outputPath"
    }
    # Keep original smoke fields for older verification consumers; the catalog
    # adds complete records for both bundled programs without a format break.
    $manifest = [ordered]@{}
    foreach ($key in $manifests[0].Keys) { $manifest[$key] = $manifests[0][$key] }
    $manifest.catalog_version = 1
    $manifest.programs = $manifests
    [IO.File]::WriteAllText((Join-Path $outputDirectory 'manifest.json'), ($manifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
} finally {
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
