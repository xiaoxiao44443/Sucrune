# Linux process support

The Android 15 application run recorded six passing cases in
`linux-fork-exec-hello-first.txt` (SHA-256
`af347e1053b1329b90abb54de1290e74674c25585dc40d6fb8b965942048d307`).
The first fork case resumed ARM64 guest code with inherited TLS, x18, FPSIMD
and COW memory. Its parent reaped exit 41. Another child extended an unlinked
file and changed its working directory while its parent retained the original
directory and read the shared file description at the expected offset. A third
child received ENOENT from a failed exec, then ran Debian GNU Hello and its
glibc interpreter. Its parent reaped status zero. That run also imported the
rootfs, exercised original Bash builtins, and loaded the original Node PTY
addon. Interactive PTY operation requires additional tests.

The subsequent Android 15 run `linux-fork-stop-managedpty-first.txt` passed
nine of ten cases (SHA-256
`f43f1c5ad797f722656f0065c7020f5ca3c699cc9cc474ca8bdb23421d65bca9`).
Official Node's asynchronous `child_process.spawn('/usr/bin/hello', ...)`
received the exact child output through a pipe and observed the spawn, exit
and close events with distinct PIDs, exit 0 and no terminating signal. The
cancellation case reaped a recorded child session leader, reached ECHILD and
reacquired its lock in the next execution. The original node-pty addon
opened a terminal pair. The interactive Bash test in that build returned
status 1 before completing its two commands.

A separate dedicated Android 15 isolated process used an SCM-transferred PTY
master to acquire the real controlling terminal, query its session, get and
set its foreground group and open its own `/dev/tty`. Its bidirectional
exchange and terminal-size checks passed. The slave descriptor was stripped
at the Android IPC boundary. See `pty-capability-ctty-master-third.txt`,
SHA-256 `9a880ba71cea781b46308eeccbf61a9fc82b0f3433c80c397ee7479a773d263f`.

## Target and upstream behavior

The first target is Node.js v24.22.2 `spawn`/`execFile` with ordinary files and
stdio. General fork-without-exec, asynchronous guest signals, job control, PTYs,
detached children and Node IPC descriptor transfer require separate capabilities.
Do not substitute Android host utilities for Linux guest programs.

The pinned [Node ProcessWrap](https://github.com/nodejs/node/blob/v24.22.2/src/process_wrap.cc)
calls `uv_spawn`. On Linux, its bundled
[libuv process implementation](https://github.com/nodejs/node/blob/v24.22.2/deps/uv/src/unix/process.c)
uses fork, child setup and `execvp`; the optimized `posix_spawn` route there is
Apple-specific. Relevant operations include:

- `UV_CREATE_PIPE` stdio uses a Unix stream socket pair, not only `pipe2`.
  A separate close-on-exec pipe communicates exec errors to the parent.
- Child setup resets signal dispositions, adjusts descriptor aliases and
  close-on-exec flags, makes child stdio blocking, optionally changes cwd or
  session/credentials, restores the signal mask, and calls `execvp`.
- SIGCHLD processing calls nonblocking waitpid. Successful exec is distinguished
  from an errno reply by EOF on the exec-error pipe.
- [Node's `child_process.fork()`](https://github.com/nodejs/node/blob/v24.22.2/lib/child_process.js)
  starts a new Node executable with an IPC channel; it is not a JavaScript heap
  snapshot API.

The supplied glibc 2.36 calls ARM64 clone syscall 220 with
`CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD`, a zero child stack and the
child TID address in argument 4. See
[arch-fork.h](https://github.com/bminor/glibc/blob/glibc-2.36/sysdeps/unix/sysv/linux/arch-fork.h),
[ARM64 argument order](https://github.com/bminor/glibc/blob/glibc-2.36/sysdeps/unix/sysv/linux/aarch64/kernel-features.h),
[fork](https://github.com/bminor/glibc/blob/glibc-2.36/posix/fork.c) and
[_Fork](https://github.com/bminor/glibc/blob/glibc-2.36/sysdeps/nptl/_Fork.c).
The guest must resume its original fork continuation so glibc and
[libuv's atfork child handling](https://github.com/nodejs/node/blob/v24.22.2/deps/uv/src/unix/signal.c)
can repair their own state. Jumping straight to libuv's child setup skips those
repairs. Linux waitpid ultimately uses
[wait4](https://github.com/bminor/glibc/blob/glibc-2.36/sysdeps/unix/sysv/linux/wait4.c).

## Recommended execution design

Use kernel COW fork from a dedicated, long-lived **host thread inside the current
runner**, followed by a restricted raw-syscall child runtime until guest exec.
At guest exec, execute the installed Bionic runner again to obtain clean host
libc and pthread state, then load the requested Linux program.

| Approach | Benefit | Main difficulty |
| --- | --- | --- |
| Dedicated fork thread in the active runner | Kernel COW retains exact guest addresses, heap, stacks and JIT state | Child inherits host runtime state from a multithreaded process; post-fork code must be tightly restricted |
| Prestarted fork-server process | Clean fork source | Does not contain the active guest address space; cannot implement its fork without transferring memory |
| New runner plus address snapshot | Starts with clean Bionic state | Requires quiescing all guest threads, copying/restoring VMAs and exact addresses, handling ASLR collisions and potentially large Node heaps |

The first approach is the smallest plausible implementation, **not a completed
safety proof**. Bionic's
[fork wrapper](https://android.googlesource.com/platform/bionic/+/master/libc/bionic/fork.cpp)
repairs selected libc state; it does not authorize arbitrary allocator or pthread
use after a multithreaded fork. The
[post-fork async-signal-safe restriction](https://man7.org/linux/man-pages/man2/fork.2.html)
must shape the child implementation. Do not assume Android applications have
ptrace, userfaultfd or process_vm access to implement the snapshot alternative.

### Fork transaction

1. Capture normalized guest CPU state and guest TLS at the clone trap. Validate
   the process-clone flag subset separately from the existing thread-only clone.
   Retain the dispatcher state lock through the fork supervisor's COW cut.
   The supervisor and raw child bootstrap run independently of that lock.
2. Prepare a bounded child record, broker session, exec/control channel and
   lifetime lease before fork. Hold short runtime/FD transaction locks only
   while taking a consistent fork snapshot; do not wait for callbacks while
   holding locks they acquire.
3. The dedicated host fork thread performs the actual fork. In the child, set
   PDEATHSIG immediately and recheck the expected parent PID. Close inherited
   temporary pins and unrelated native descriptors from a precomputed allowlist.
4. Reinitialize child-owned runtime/gate state using raw, bounded operations.
   Never destroy copied `guest_threads` objects or acquire copied parent mutexes.
   The surviving fork thread retains its Bionic TLS and Android baseline
   filter. It starts a raw execution thread with a private signal stack and
   the guest seccomp filter. A real kernel signal frame restores the guest's
   registers, inherited SP and TLS with x0 = 0. The parent receives the
   actual child PID.
5. Write guest child TID independently of Bionic's own clear-child-TID address.
   The initial post-fork dispatcher supports only the documented fork-to-exec
   syscall subset and `_exit`; no host malloc, JNI, Go, or pthread creation.

This preserves Linux guest atfork continuations and COW memory while avoiding
attempts to reuse vanished host pthreads. The fixed fork thread must remain alive
until its children have been accounted for: PDEATHSIG is tied to that thread.

### Exec preparation and commit

Validate bounded path, argv/env, ELF/interpreter and inherited descriptor state
before irreversible replacement. A failed preflight returns the appropriate
guest errno so `execvp` can try another PATH entry. Preserve supplied argv[0]; the
current convenience launch API that prepends a program path is insufficient.

The baseline-filter supervisor commits by host-executing the installed runner with a bounded FD-based startup
message. Sealed memfds contain the validated program and interpreter, so
renaming or replacing the project paths cannot redirect the receiver. The
physical PID stays the same, old address space and stale Bionic locks disappear,
and the new runner can create its normal thread supervisor. On successful guest
exec, apply close-on-exec flags, reset caught signal dispositions, retain ignored
dispositions and the guest mask, and install the new guest image/TLS. See
[execve semantics](https://man7.org/linux/man-pages/man2/execve.2.html).
Failure after irreversible host exec is a fatal child startup failure, not an
errno return to the discarded guest image. The exec-error handshake must make
this distinction observable.

## Broker and descriptor ownership

Each guest process has a private manager SOCK_SEQPACKET session. FORK_SESSION
copies its working directory and handle table. Duplicating each kernel file
description preserves offset, locks and unlinked files across the COW cut.
Guest FD_CLOEXEC belongs to the individual alias. Before a child exec, its
sender selects the resources that retain at least one surviving alias and
marks the rest for release. The fresh receiver commits that child's broker
session after validating its startup packet and restores the virtual FD table.
Transferred local aliases keep their kernel open descriptions and epoll keys.

The manager creates PTY masters and transfers them through SCM_RIGHTS. The
manager retains the actual slave and serves typed file/termios operations for
its session-local handle. A session leader can borrow the corresponding master
temporarily, acquire its real controlling terminal and open `/dev/tty` under
its isolated identity. The kernel handles the terminal's foreground group and
line discipline. The runtime validates the admitted PTY and process group for
control operations. Final guest master close releases the matching manager
reference so the peer observes hangup.

## Waiting and cancellation

A fork request reserves a bounded child slot and starts a waiter for that PID.
The watcher blocks in `waitid(WEXITED | WNOWAIT)`, records kernel SIGCHLD
information and signals a private eventfd. The PID remains reserved until a
tracked guest wait4 or cleanup reaps it. Blocking guest wait4 releases the
runtime state lock. Standard SIGCHLD notifications coalesce. An epoll waiter
can wake on either its own object or the private eventfd. Neither includes the
runtime event in guest output. Raw pselect6 maps guest FD sets to retained host
aliases and applies the temporary mask to guest signal state. Its sigreturn
frame restores the caller's mask after interruption.

Exec re-arms PDEATHSIG and checks the expected parent. Each physical guest
process exits with the guest's status. The external owner also checks real
process termination and release of task resources. Process-group signalling
alone misses children that start a new session. The cancellation test covers a
session-leading child, physical reaping, ECHILD and subsequent project reuse.

## Android 15 acceptance

`linux-fork-pty-pselect-third.txt` passed all eleven cases. SHA-256
`a926e29f9cf39f4fc9e2b0d245440a6094e37475243d66cc186bd1658b0279e9`.
The original Node PTY addon started Debian `/bin/bash --noprofile --norc -i`.
The Bash PID stayed stable, all three standard streams passed its TTY checks,
and shell state persisted across two commands before the parent collected
exit 7. Another original Node spawn passed an already-connected TCP socket to
Bash, then wrote to the same connection after Bash exited. These cases extend
the preceding Node spawn, COW, file, exec and cancellation measurements.

Coverage applies to the described guest clone/exec subset. Additional work
includes broader signal delivery during blocking syscalls, pipelines with
multiple job-control process groups, general guest SCM_RIGHTS, shared-network
resource classes beyond the tested TCP case and Linux program behavior before
exec outside the supported dispatcher. Android versions and page sizes require
their own device measurements.
