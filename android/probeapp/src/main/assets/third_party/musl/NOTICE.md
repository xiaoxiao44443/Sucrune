# musl and Zig runtime notice

The trusted `sucrune-musl-smoke.elf` fixture and `sucrune-lua.elf` interpreter
statically link the musl-based Linux libc supplied by the official Zig 0.17.1
Windows x86_64 release. This combines musl startup, TLS and other routines with
Zig-provided libc implementations, including the allocator, and compiler runtime
support. Sucrune does not modify these toolchain sources. The complete linked
libc must not be described as unmodified upstream musl or Bionic.

- musl project: https://musl.libc.org/
- Zig release: https://ziglang.org/download/0.17.1/
- Pinned archive: `zig-x86_64-windows-0.17.1.zip`
- Archive SHA-256: `b03f477a1943673e02aca0f570e8030dffd536ce1f45cbc4d3326ec31159562e`

`COPYRIGHT` is copied verbatim from `lib/libc/musl/COPYRIGHT` in that archive,
including contributor notices and third-party attribution. `ZIG-LICENSE` is
copied verbatim from the archive's top-level `LICENSE`. Keep both notices with
distributed artifacts containing either statically linked program. The fixture's
source and build recipe are in `native/programs` and `scripts/build-linux-programs.ps1`;
Lua source and its separate MIT license are in `third_party/lua`.

Sucrune's runtime implementation remains separate from musl; linking this test
program does not mean that arbitrary libc programs are supported.
