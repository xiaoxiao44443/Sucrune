# Sucrune guest shell

This is a freestanding Linux/AArch64 program, loaded as a relocation-free
`ET_DYN` ELF. It has no Android, libc, or host-broker symbol dependencies.
It is a deliberately bounded shell subset, not POSIX `sh` or Bash.

## Invocation and syntax

`sh -c SCRIPT`, `sh FILE`, and `sh --help` are supported. Scripts support:

- Newline and semicolon command separators; comments beginning at a word boundary.
- Single and double quotes, backslash escapes, and backslash-newline continuation.
- Assignment-only commands, including `A=hello B=$A`; `$NAME`, `${NAME}`, and `$?`.
- `&&` and `||` with left-to-right short-circuit behavior.
- At most one stdin file redirection `<` and one stdout file redirection `>`
  or `>>` per command, applied in lexical order. They also apply to commands
  inside nested `sh` or `source` invocations and to successful `exec`.

Expansion does **not** perform field splitting: one input word remains one
argument, including an empty expansion. Unsupported syntax is explicitly
rejected: pipelines, background jobs, command substitution, subshells,
compound commands/loops, descriptor redirection or here-documents, unquoted glob
patterns, tilde expansion, positional parameters, and command-prefix
assignments such as `A=value command`. Use `A=value; command` instead.

Each command is lexed before that command performs I/O. Earlier completed
commands retain their effects when a later command fails to parse. This is
not whole-script transactional validation. A missing final command after
`&&` or `||` is detected after the preceding command has run.
Both redirection paths are expanded before redirection I/O. After that,
redirections take effect in source order: `cat > out < missing` may truncate
out before the failed input open, while `cat < missing > out` leaves out alone.
Duplicate input/output redirects and unsupported redirection syntax are rejected
before the current command opens files.

## Builtins

| Command | Supported behavior |
| --- | --- |
| `echo [-n] ...` | Literal arguments separated by spaces; use `printf` for escapes |
| `printf FORMAT ...` | `%s`, `%%`, `\n`, `\r`, `\t`, `\\`; format repeats while `%s` arguments remain |
| `pwd`, `cd PATH` | Project-relative virtual working directory; `/` is the project root |
| `cat [--] [FILE\|-]...` | No paths or `-` reads current stdin; `./-` names a file; finite byte streams only, no PTY |
| `ls [-a] [DIRECTORY]` | One name per line, host directory order; always omit `.` and `..` |
| `mkdir [-p] [--] PATH...` | Create directories; `-p` verifies existing components are directories |
| `touch [--] FILE...` | Ensure files exist; existing timestamps are not updated |
| `rm [-f] [--] FILE...` | Unlink files; `-f` ignores missing files; no recursive or directory removal |
| `cp SOURCE DESTINATION` | Copy file bytes; reject directories and the same normalized path; no metadata preservation |
| `mv SOURCE DESTINATION` | Rename paths; no options or cross-filesystem copy fallback |
| `true`, `false`, `exit [0..255]` | Exit status and explicit script termination |
| `sleep 0..60` | Integer seconds; interruption returns failure; cancellation belongs to the host supervisor |
| `source FILE`, `. FILE` | Execute in the current variable/working-directory scope |
| `sh -c SCRIPT`, `sh FILE` | Execute a nested script, then restore caller variables and cwd |
| `exec /bin/lua ARGS...`, `exec /bin/musl-smoke ARGS...`, `exec /bin/sucrune-sh ARGS...` | Replace the entire guest image with a fixed bundled program; success never returns |
| `help` | Print the supported subset |

There is no fork, external executable search, job control, shell
function, alias, or process pipeline. Nested `sh` provides a variable/cwd
scope inside this guest process; it is not a separate process or security
boundary. Filesystem changes persist. Hard-link alias detection for `cp` is
not implemented; the current runtime does not create hard links.

`exec` invokes Linux `execve`, using the explicit absolute path as argv[0].
The runtime resolves the three reserved executable paths above to fixed bundled
ELFs; it never executes an arbitrary project or host binary. No PATH search or
automatic external-command fallback occurs. All current shell variables are
exported as environment entries, including inherited variables and later
assignments; this subset has no separate `export` attribute. Virtual cwd and
eligible descriptors are inherited by the replacement image.
Executable paths match exactly without normalization or symlink traversal.
They are not materialized as project `/bin` files: open/stat still use project
file lookup, while exec never reads executable bytes from that lookup.

On success, even `exec` inside a nested `sh` or `source` replaces the entire
guest: neither its remaining commands nor the caller resume. On failure, the
current shell remains usable, returning 127 for ENOENT and 126 for other syscall
errors; `;` and `||` can handle that result. Missing or non-absolute paths are
usage errors (status 2).

Redirection uses real Linux descriptor operations, not an alternate output
parameter passed to a builtin. Shell saves affected fd 0/1 using
`F_DUPFD_CLOEXEC`, remembers their original descriptor flags or closed state,
opens the selected file, and uses `dup3` to replace the standard descriptor.
Returned builtins, nested frames and failed exec restore the original mapping
and flags, including partial setup failures; a restoration failure aborts the
script. Successful exec retains the mapped standard streams and closes every
saved backup through CLOEXEC, so no hidden copy keeps the original input alive.
Normal redirection side effects, including output creation/truncation before
an exec failure, are retained.

For example, this prepares a project script and then transfers execution to Lua:

```sh
mkdir output
echo input > data.txt
printf '%s\n' 'io.write(assert(io.read("*a")));print("from Lua")' > task.lua
exec /bin/lua task.lua < data.txt > output/result.txt
```

## Bounds and results

- Script input: at most 65,536 bytes; script files containing NUL are rejected.
- Per-command expanded words, including redirection: less than 8,192 bytes.
- At most 64 command arguments, 64 variables, names up to 63 bytes, values
  up to 1,023 bytes; paths fit the runtime's 1,024-byte path buffer.
- `exec` uses fixed environment scratch storage. Runtime limits on the combined
  argv/environment size still apply and may return E2BIG without replacing the image.
- At most four frame slots; top-level file loading currently occupies slot 1.
  Nested `sh -c` also obeys the per-command expansion limit.
- stdout and stderr are raw bytes. Diagnostic lines begin `sucrune-sh: `.
- Status 2: syntax, unsupported feature, usage, or size-limit error.
  Status 127: unknown command or exec ENOENT. Status 126: other exec failure.
  Status 1: filesystem/I/O operation failure.
  `exit` can explicitly return any value from 0 through 255.

No data-dependent allocation or libc calls occur. Runtime data uses bounded
ELF BSS storage and the guest stack. Generated ARM64 code must be built with
`-ffixed-x18`, and the startup assembly does not change `x18` or `TPIDR_EL0`.

## Linux syscall contract

`read(63)`, `write(64)`, `openat(56)` with `AT_FDCWD`, `close(57)`,
`getdents64(61)`, `mkdirat(34)`, `unlinkat(35)`, `renameat(38)`, `chdir(49)`,
`getcwd(17)`, `nanosleep(101)`, `dup3(24)`, `fcntl(25)` with
F_GETFD/F_SETFD/F_DUPFD_CLOEXEC, `execve(221)`, and `exit(93)`.

Reads and writes handle partial results; Linux negative errno values are
preserved for diagnostics. `getcwd` uses the Linux syscall convention of
returning the byte count including NUL. Paths and all filesystem permissions
are enforced by the host runtime, not by guest string processing.

## Validation

`tests_host.c` compiles on a C11 host and runs the actual shell parser and
builtins against mock Linux syscalls. The mock deliberately returns short
reads and writes and models shared open descriptions, offsets, reference counts,
per-descriptor CLOEXEC and standard stream routing. Every returned case checks
restored standard descriptor state, accurate references and no leaked backup FDs.
It does not establish ARM64
execution, Android behavior, broker isolation, or real filesystem semantics.
The exec mock captures argv/environment/cwd and models non-return with a test
longjmp after applying mock CLOEXEC; it does not load an ELF or run any host
interpreter/process. The 0.6 implementation passes 72/72 host checks, including
the former 44 cases with the three old exec-redirection rejection expectations
updated to supported behavior, plus 28 new redirection/input checks.

On Linux, an example is:

```sh
cc -std=c11 -Wall -Wextra -Werror -O0 tests_host.c -o shell-host-tests
./shell-host-tests
```

On Windows with MSVC and the Windows SDK installed, from the project root:

```powershell
.\native\shell\test-host.ps1
# If cl.exe is not on PATH, pass -Compiler with its full path.
```

The script finds the installed SDK version and writes artifacts only under
the project's `.build/shell-host-tests`. It restores the caller's environment.
`tests_host.c` is a separate host-test translation unit; it is never passed
to the ARM64 guest linker.

`tests.json` contains representative scripts for Android runtime tests.
Run filesystem cases inside a newly created disposable project. After recording
concise results, delete that test project and temporary logs/screenshots. The
current user preference is to keep both application and test packages installed,
retain their signing key, and use adb install -r for subsequent builds. Do not
uninstall or use pm clear; persistent in-app execution history is retained.
