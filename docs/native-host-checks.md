# Native checks on development hosts

Windows requires 64-bit PowerShell, CMake 3.22+ with CTest, and an installed
Visual Studio MSVC toolchain supporting C11 atomics. The current verified host
uses Visual Studio 2026 / MSVC 19.51. No Android SDK or device is used:

```powershell
./scripts/test-native-host.ps1
# If CMake's default generator is not the installed Visual Studio version:
./scripts/test-native-host.ps1 -Generator 'Visual Studio 18 2026'
```

The script configures a unique build directory, compiles with warnings as errors,
runs six CTest groups and writes `.build/native-host-check.json` with source
hashes and actual test output. It deletes its temporary build directory by
default; `-KeepBuild` retains it for investigation. Sources changing during the
run invalidate the result. The report never represents app/device validation.

| Group | What Windows verifies | What it does not verify |
| --- | --- | --- |
| Guest space | VMA policy, interval/rollback invariants and Windows memory adapter | Linux mmap behavior, Android executable mappings or guest JIT |
| Guest signals | Normalized signal state and frame validation model | Native signal delivery, TLS restoration or Android signal chains |
| Guest FDs | Ownership, aliases and table transactions | Kernel file/pipe behavior |
| Gate registry | Real Windows thread contention and atomic publication | ARM64 signal-entry assembly |
| Linux filter | Interpreter decisions from the actual source-generated BPF | Filter installation or inherited Android seccomp precedence |
| Network probe addresses | Exact IPv4, IPv6 and IPv4-mapped IPv6 loopback recognition | Android socket permissions or actual network transfer |

Linux can additionally compile and run the existing shell/broker/ELF/probe
checks, real local pipe/eventfd/epoll checks and the Linux ELF parser:

```sh
cmake -S native -B .build/native-linux -DCMAKE_BUILD_TYPE=Debug
cmake --build .build/native-linux --parallel
ctest --test-dir .build/native-linux --output-on-failure
```

The Linux guest-thread test requires ARM64 and returns CTest's configured skip
code on other architectures. It executes host-native guest thread entry, so it
also needs the Linux kernel's signal/seccomp facilities. The ELF parser test
reads ARM64 hello/loader/libc/Node files as data on either Linux architecture and
checks 4 KiB/16 KiB plans; it does not execute them. CTest registers this parser
test only when all four official rootfs files exist. The executable is still
built if fixtures are absent; CMake prints the omission. Override their root
with `-DSUCRUNE_LINUX_TEST_ROOTFS=/path/to/rootfs/files`.

The Linux wiring is separate from Android targets. A successful Windows run does
not mean the Linux-only tests ran; Linux execution must have its own evidence.
Use Android app instrumentation to establish packaged runner execution, inherited
filters, Linux workloads and task lifecycle. UID 2000 shell probes are useful
mechanism checks but are not equivalent to the ordinary/isolated app identity.
