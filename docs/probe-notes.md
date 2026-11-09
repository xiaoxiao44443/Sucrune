# Native syscall probe

This is diagnostic scaffolding for the first milestone, not a Linux runtime or
a security sandbox. The production runtime's portable core can remain Go.
This fixture uses a small C signal handler and an architecture assembly stub so
that the first Android host-capability experiment does not depend on integrating
with Go's signal ownership, scheduler, garbage collector, and stack management.

## Experiment

Run `com.sucrune.probe.NativeProbe.runProbe()` only in a disposable Android service
process. The caller must supervise the process, report binder death/timeouts,
and terminate it after receiving the result. Run both the ordinary-app service
and the isolated service to compare their actual host policies.

The JNI caller temporarily installs a process-wide `SIGSYS` handler, then creates
one native pthread. That thread installs an alternate signal stack with guard
pages, confirms baseline `getpid` and `gettid`, enables `no_new_privs`, and adds a
seccomp filter to **that thread only**. The filter traps only `getpid` from the
resume PC of `sucrune_probe_getpid` in `trap.S`. It permits the other syscalls at this
layer; previously inherited Android filters still apply. This instruction-address
selection is a controlled experiment and is not a security boundary.

The signal handler checks the signal code, filter tag, syscall number, and ABI,
records whether it ran on the alternate stack, and writes `424242` into x0 on
ARM64 or RAX on x86_64. It neither replays the syscall nor calls Go, JNI, allocators,
logging, or mutexes. It leaves PC unchanged because the kernel already advanced
past the syscall instruction. Returning invokes the platform signal restorer.

The worker verifies the synthetic result and exactly one signal, then checks that
ordinary libc `syscall(SYS_getpid)` still returns the real PID and `gettid` is
unchanged. The pthread exits with its irreversible filter. Only after joining the
thread does the JNI caller restore the original signal handler and free the
alternate stack. A mutex rejects overlapping probe invocations.

An unexpected `SIGSYS` terminates this disposable process instead of treating an
Android policy rejection as a successful emulated operation. An impossible-to-
recover join failure also terminates the process to avoid freeing live thread
state. The Android supervisor must classify missing reports as failed or unknown.

## Report

The method returns a JSON string with `schema_version`, `probe`, `status`, `stage`,
`error_number`, `message`, `host`, and `evidence`. `status` is `passed`, `failed`, or
`unsupported`. `unsupported` at `seccomp_install` means this installation attempt
was rejected; it does not establish that every possible interception backend is
unavailable. Host fields include ABI, kernel, page size, UID, PID, and inherited
seccomp/no-new-privileges values. Evidence includes the expected and observed
return values, signal information, control calls, and cleanup outcomes.

Success proves this narrowly selected round trip under the tested kernel and
process identity. It does not prove arbitrary ELF loading, general syscall
emulation, process virtualization, thread safety of a future Go integration, or
cross-project isolation. These require separate probes and acceptance tests.

## Build and verification

The Android app builds `native/CMakeLists.txt` through the NDK for `arm64-v8a` and
`x86_64`. The library requests 16 KB ELF segment alignment; actual 4 KB and 16 KB
execution environments still need validation.

On a Linux x86_64 or ARM64 host with a C compiler, the same CMake project builds
`sucrune_probe_cli`. Configure and build it, then run `ctest --test-dir <build-dir>
--output-on-failure`. CTest enforces a 10-second timeout. This checks the core on
that Linux host, not Android's ordinary/isolated app policies.

## Primary references

- [Linux seccomp filter semantics](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Android bionic signal-context layouts](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/include/sys/ucontext.h)
- [Android 16 KB page-size compatibility](https://developer.android.com/guide/practices/page-sizes)
