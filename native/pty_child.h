#ifndef SUCRUNE_PTY_CHILD_H
#define SUCRUNE_PTY_CHILD_H
#include "pty_runtime.h"
/* Private, single-threaded post-fork continuation only. FD lookup returns
 * the current guest slot's retained host alias, kind and kernel PTY number;
 * unrelated/closed entries return -ENOTTY/-EBADF. publish owns the alias
 * only on success and records metadata for dup/close/exec. copy validates
 * the complete logical guest VMA range before copying. raw returns -errno.
 * Callbacks (and their implementation) must not access Bionic or host locks. */
struct sucrune_pty_child_ops {
    void *context;
    long (*raw)(long, long, long, long, long, long, long);
    int (*lookup)(void *, unsigned int, struct sucrune_pty_endpoint *);
    int (*publish)(void *, int, enum sucrune_pty_kind, int, uint64_t);
    int (*copy)(void *, uintptr_t, void *, size_t, int to_guest);
    int (*allow_group)(void *, int);
};
long sucrune_pty_child_ioctl(const struct sucrune_pty_child_ops *, unsigned int guestfd,
                             uint64_t command, uint64_t argument);
/* path is a checked, bounded, NUL-terminated HOST copy. Unrecognized paths
 * return -ENOENT. Only pass recognized PTY paths here. */
long sucrune_pty_child_open(const struct sucrune_pty_child_ops *, const char *path, uint64_t flags);
long sucrune_pty_child_setsid(const struct sucrune_pty_child_ops *);
#endif
