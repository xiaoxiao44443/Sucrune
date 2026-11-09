# Lua 5.4.9

Lua is maintained by Lua.org / PUC-Rio and distributed under the MIT license.
The `src` directory and `UPSTREAM_README` are unmodified files from the official
Lua 5.4.9 release of 10 August 2026. `LICENSE` reproduces the notice in `src/lua.h`.

- Release archive: https://www.lua.org/ftp/lua-5.4.9.tar.gz
- Official release checksums: https://www.lua.org/ftp/
- SHA-256: `2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6`
- Archive size: 373429 bytes.
- Reference manual: https://www.lua.org/manual/5.4/manual.html

`SOURCE.json` records the verified archive and each vendored file's SHA-256.
The build script verifies these source hashes before compiling. It compiles
the upstream standalone interpreter (`lua.c`), excluding only the separate
bytecode compiler entry point (`luac.c`), with Zig 0.17.1 and its musl-based Linux libc.
No Lua C source is patched and no Android or host-shell substitute is used.

The POSIX build configuration enables normal file and terminal interfaces.
Dynamic C module loading and readline are not compiled in. This release is
bundled as a trusted ARM64 static ELF for Sucrune's current runtime subset;
it does not imply support for child processes, arbitrary executables, guest
signals or every Lua OS/I/O feature. Pure Lua modules use project files.

Musl and Zig runtime notices are in the neighboring `third_party/musl` directory.
This notice and `LICENSE` are also packaged as Android assets.
