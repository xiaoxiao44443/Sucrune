#ifndef SUCRUNE_GUEST_FORK_ARENA_H
#define SUCRUNE_GUEST_FORK_ARENA_H
/* The raw supervisor stack, worker stack and kernel signal altstack all live
 * in this aligned reservation. The signal gate can recover its own context
 * without libc TLS, a PID table or process-global writable scratch. */
#define SUCRUNE_FORK_ARENA_BYTES 0x200000
#define SUCRUNE_FORK_SUPERVISOR_TOP 0x160000
#define SUCRUNE_FORK_WORKER_TOP 0x1a0000
#define SUCRUNE_FORK_ALT_BASE 0x1b0000
#endif
