# Trusted Linux programs

The APK embeds two trusted Linux ARM64 programs: `musl-smoke` and upstream
Lua 5.4.9 (`lua`). Neither calls Android APIs or replaces libc startup with a
Sucrune implementation. Lua's vendored upstream source is unmodified.
This is not an arbitrary executable import API; Lua scripts are project files.

Both programs link Zig 0.17.1's **musl-based Linux libc**. It combines musl
startup, TLS and other routines with Zig-provided libc implementations. In the
smoke fixture, `malloc`/`free` resolve to Zig's `c/malloc.zig` and SmpAllocator,
not the upstream musl allocator. See the binary-level provenance clarification
in [the historical libc record](../../docs/validation/android15-libc.md).
Sucrune does not modify these toolchain libc sources or link guest code to Bionic.

## Build

Use the official Windows x86_64 Zig 0.17.1 archive:

- Download: https://ziglang.org/download/0.17.1/zig-x86_64-windows-0.17.1.zip
- SHA-256: `b03f477a1943673e02aca0f570e8030dffd536ce1f45cbc4d3326ec31159562e`
- Expected archive size: 100343666 bytes.
- Upstream release metadata: https://ziglang.org/download/index.json

Verify the checksum before extracting it. No system installation is needed.
Zig includes the musl sources, Zig libc implementations and Linux headers used
for this target; the Android NDK's Bionic libc is not used to link the guest.

Lua source provenance:

- Official release: Lua 5.4.9, 2026-08-10.
- Archive: https://www.lua.org/ftp/lua-5.4.9.tar.gz
- SHA-256: `2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6`.
- Archive size: 373429 bytes.
- Vendored source and per-file checksums: `third_party/lua`.

The build verifies the vendored source manifest before compilation. Lua is
compiled with `LUA_USE_POSIX` and linked with `-lm`; it does not define
`LUA_USE_LINUX`, `LUA_USE_DLOPEN` or `LUA_USE_READLINE`. The `luac` executable is
not built or exposed. Lua/Zig/musl licenses and notices are packaged in the APK.

```powershell
.\scripts\build-linux-programs.ps1 -Zig 'C:\Tools\Zig\zig.exe'
.\scripts\build-android.ps1 -Zig 'C:\Tools\Zig\zig.exe' -Go 'C:\Tools\Go\bin\go.exe' -JdkHome 'C:\Tools\JDK' -SdkRoot 'C:\Android\Sdk'
```

The first command writes `.build/linux-programs/sucrune-musl-smoke.elf`,
`sucrune-lua.elf` and `manifest.json`. It checks each generated ELF type, architecture, image base,
LOAD permissions/alignment, TLS presence and absence of an interpreter or
dynamic segment. The manifest records source/artifact SHA-256 and the actual
program headers. Zig caches and temporary output stay under `.build`.

The guest is AArch64 ET_EXEC, statically linked, with a fixed base of
`0x20000000` and 16 KB LOAD alignment. It is not PIC/PIE. Loading must reserve
the required address range without replacing existing mappings, then fail
explicitly if that reservation is unavailable. The linker retains a real
PT_TLS and musl's ordinary startup. A TLS segment may contain only zero-filled
data; Lua's current image has a four-byte zero-initialized TLS region and no
file-backed TLS bytes. CMake fails with the build command if the ELFs have not
been generated before an ARM64 Android build.

## Fixed-image execve contract

The guest may issue Linux ARM64 execve(221) to exactly `/bin/lua`,
`/bin/musl-smoke`, or `/bin/sucrune-sh`. The latter selects the freestanding
Shell; it is an exec-only entry, not a new public executeProgram identifier.
Public catalog entries for Lua/smoke include their reserved `path`.

These are exact virtual executable names, not an installed `/bin` rootfs.
No path normalization, symlink traversal, PATH search, shebang, dynamic linker,
or project ELF loading occurs. open/stat on the same text still use the project
file broker; exec never loads those files' bytes.

Before handoff, path/argv/envp are checked and copied while the old image is
valid: up to 65 argv entries including argv[0], 64 environment entries, and
65,536 total string bytes including NUL. Bad pointers, oversize vectors, and
unknown paths return errno without changing the old image or descriptor state.
Once irreversible replacement begins, memory/loading/broker failure terminates
the execution as native failed/manager lost; it cannot resume unloaded code.

A successful exec retains the worker PID/TID, cwd, virtual signal mask, remaining
stdin, and non-CLOEXEC file descriptors with their offsets. Guest CLOEXEC applies
to file and standard descriptors at commit. Image BSS, TLS, stack and data arena
are reinitialized. The existing execution ID, deadline, cancellation, syscall
budget and four final cleanup barriers span the chain; at most 32 replacements
succeed, after which execve returns ELOOP. There is no fork/wait or subprocess.

Reports keep the initial request `kind`, and add `last_program`, `exec_count`,
`exec_limit` and `host_context_restores`. Shell's `exec` exports all current
variables and requires an absolute path. Each command supports at most one
input `<` and one output `>`/`>>`; other descriptor syntax is rejected. File
redirection changes real fd 0/1 and is inherited by successful exec, including
from nested shell frames. Success never returns; failed exec restores Shell's
standard descriptors while retaining completed file creation/truncation.

## Descriptor and stream contract

Each execution has 64 guest descriptor slots, numbered 0–63. They are separate
from opaque broker handles and host file descriptors. dup(23), dup3(24), and
fcntl(25) F_DUPFD/F_DUPFD_CLOEXEC share one open description, offset and status
flags. FD_CLOEXEC is per descriptor; F_GETFD/F_SETFD does not change an alias's
flags. F_GETFL reads shared status. Broker regular files/directories support
O_APPEND and guest-visible O_NONBLOCK; the manager keeps its internal nonblocking
safeguard set regardless. O_ASYNC and pipes are unsupported in this bundled
program profile; the separate Linux profile implements local pipe/event I/O.

Allocation uses the lowest free descriptor, including closed 0/1/2. Invalid
dup3 arguments leave the destination intact; a full table returns EMFILE before
open can create or truncate a path. The final alias close releases the resource;
closing fd 0 alone does not release stdin if a guest alias still references it.
Output capture PFDs remain owned by the Kotlin worker until final cleanup.
File descriptors remapped onto standard numbers retain file read/write/seek/stat
semantics; aliases of the original streams retain their direction and ESPIPE.

Shell backs up affected descriptors with F_DUPFD_CLOEXEC before remapping.
Returned builtins/nested frames and failed exec restore mappings, original flags
and originally closed state. Successful exec closes all backups, including those
from outer frames, so none keep the original stdin reader alive. Normal native
reports include fd_limit=64, fd_peak and post-cleanup fds_live/resources_live.

## Lua contract

`executeProgram(envId, "lua", argv, env, cwd, timeoutMs, stdin)` prepends `lua`
as argv[0]. The remaining arguments follow upstream Lua command-line syntax:
`["-e", "print(1 + 2)"]`, `["/scripts/task.lua", "argument"]`, or `["-"]`
to interpret finite stdin. Input is a copied ByteArray of at most 1 MiB; no
interactive terminal or later input writes are exposed. `listPrograms()` returns
the native bundled catalog, shared by validation and the UI.

Project scripts can use loops, functions, tables, string/UTF-8 routines, Lua
coroutines and pure Lua modules through `require` and a project `LUA_PATH`.
Coroutines do not create guest OS threads. Files remain under the current
project's broker; `os.rename` and `os.remove` use existing broker operations.
Create the project directory `/tmp` before using `io.tmpfile()`.

No dynamic C modules, readline, external processes, network stack or package
installation is provided. `os.execute` and `io.popen` have no supported subprocess
backend. `os.clock()` reads worker process CPU time, not an isolated guest quota.
Lua's attempted SIGINT handler registration remains unsupported; cancellation
and timeouts terminate the disposable worker through the Android supervisor.

Ordinary Lua success exits 0; script syntax/runtime failures are nonzero and
write stderr. A failure does not roll back project writes already completed.
The runtime does not claim to safely execute malicious Lua source or bytecode.

## musl-smoke contract

The runtime prepends `musl-smoke` as argv[0].

- `selftest [value]` (also the default): tests argv and `SUCRUNE_TEST`, buffered
  stdout/stderr, initialized and zero-initialized thread-local variables,
  `errno` and a deliberate Linux x18 register value across syscall traps,
  virtual FD_CLOEXEC get/set round trips, 1 MiB malloc/free, anonymous mmap/mprotect/munmap,
  and fopen/write/seek/read/stat. It writes `libc-result.txt` with the UTF-8
  content `Sucrune musl: 中文🙂` plus one newline. It also checks unreadable
  syscall pointers, forbidden executable/oversized memory, code/stack protection
  boundaries, and zero-filled memory after unmap/remap. Successful exit status is 42.
- `echo [args...]`: prints arguments separated by one space and a newline;
  successful exit status is 0.
- `sleep seconds`: accepts an integer from 0 to 60, flushes
  `musl:sleep=start\n`, sleeps using libc nanosleep, prints
  `musl:sleep=done\n`, and exits 0. This supports real cancellation/timeout tests.
- `fault`: flushes `musl:fault=start\n`, then deliberately faults while musl TLS
  is installed. The worker must terminate; the manager records lost without a
  normal exit code and waits for worker death, stream EOFs, broker completion and stdin feeder closure
  before allowing reuse. This mode does not install a guest signal handler.
- `--close-stdin-loop`: closes guest FD 0, flushes `closed\n`, then runs a CPU-only
  NOP/branch loop until cancellation or timeout. This verifies that the manager's
  input feeder finishes while the guest is still alive. Upstream Lua intentionally
  refuses to close its standard file objects, so Lua is not altered to expose this
  low-level fixture behavior.
- `exec-path PATH [args...]`: calls execve with the explicit target and current
  environment; successful replacement does not return to the fixture.
- `--exec-state`: replaces itself and checks PID/TID, cwd, non-CLOEXEC file
  offsets, file/stderr CLOEXEC, fresh TLS/BSS/arena, remaining stdin, the virtual
  SIGUSR1 signal mask, and custom argv[0] independently of AT_EXECFN.
- `--exec-errors`: probes ENOENT/EFAULT/E2BIG and checks that failed requests
  leave the old memory/TLS/descriptor state usable.
- `--exec-stdin-cloexec`, `--exec-stdout-cloexec`: apply standard-descriptor
  CLOEXEC and verify EBADF after self replacement, reporting on the other stream.
- `--exec-chain`: replaces itself 32 times, expects ELOOP at the next request,
  then prints `exec:chain=32` and exits normally.
- `--fd-aliases`: verifies lowest-slot dup/fcntl allocation, shared offsets and
  O_APPEND, independent CLOEXEC, dup3 replacement, and final-reference close.
- `--fd-errors`: verifies invalid arguments, unchanged dup3 targets, descriptor
  exhaustion, hole reuse and absence of file side effects on full-table open.
- `--fd-exec-aliases`: replaces itself, checks per-descriptor CLOEXEC and surviving
  shared offsets, and prints `fd:exec-aliases=ok` after final-alias cleanup.
- `--fd-stdio`: expects finite input `stdio-input\n`; verifies original stream
  aliases, stdout-to-stderr routing, file reuse of fd 0/1 and access/seek errors.
- `--fd-stdin-alias-loop`: closes fd 0 while holding an input alias, prints
  `fd:alias-open`, waits one second, closes the alias, prints `fd:alias-closed`,
  then enters a CPU-only loop. The feeder must finish after the final alias
  closes while this worker remains alive; cancellation is required to stop it.
- `--fd-capacity`: closes all three standard descriptors, opens 64 independent
  files at fd 0–63, checks EMFILE and slot reuse, then writes
  `fd:capacity=64\n` to `fd-capacity-result.txt`. It has no captured output.
- Invalid mode or sleep arguments return 2. A selftest failure returns 1 and
  writes `musl:fail=<step> errno=<number>` to stderr.

Successful selftest stdout is:

```text
musl:argv=<value, empty when omitted>
musl:env=<SUCRUNE_TEST, empty when absent>
musl:tls=ok
musl:memory=ok
musl:file=ok
musl:ok
```

Stderr is `musl:stderr=ok\n`. The two streams are independent; their relative
arrival order is unspecified. Source compilation and header checks alone do
not establish device execution, security isolation, or general musl compatibility.

Licenses and provenance are preserved in [third_party/musl](../../third_party/musl/NOTICE.md)
and [third_party/lua](../../third_party/lua/NOTICE.md).

Android `probe=program` contains seven integration groups, including genuine
fault cleanup. See [device validation](../../docs/device-validation.md) for the
commands and [the historical libc record](../../docs/validation/android15-libc.md) for
0.3.0 results. The Lua/stdin suite contains ten integration groups;
the historical 0.4.0 validation passed 37/37 on Android 15 ARM64 with 4 KB pages.
See [the tools record](../../docs/validation/android15-tools.md) for exact scope,
artifacts and remaining device configurations. A host build alone does not count
device tests as passed.

Version 0.5.0 adds eleven `probe=exec` groups; the full application-identity
regression passed 48/48 on Android 15 ARM64 with 4 KB pages. Build/device results
and cleanup status are recorded separately in the
[exec validation record](../../docs/validation/android15-exec.md).

Version 0.6.0 adds twelve `probe=io` groups for aliases, capacity, Shell file
streams, exec inheritance and last-reader cleanup. Its 60 application-identity
checks (12 new plus 48 regressions) passed on the same non-debuggable Android 15
ARM64/4 KiB validation APK. Host Shell 72/72 and pure FD 10/10 checks do not
establish Android guest execution. The separate broker test
passed under adb shell/UID 2000 and is not application-identity evidence. Current
results, completed final artifact/log audits and cleanup are recorded in
[IO validation](../../docs/validation/android15-io.md).
