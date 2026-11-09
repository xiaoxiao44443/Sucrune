#ifndef SUCRUNE_PTY_SESSION_H
#define SUCRUNE_PTY_SESSION_H
#include "guest_fds.h"
#include "pty_runtime.h"
struct sucrune_process_group;
/* For the dedicated isolated Linux runner, never call on the Android manager.
 * Caller serializes complete broker request/reply transactions. open requires
 * the FD table lock, preflight before calling, and release if publication
 * fails. Each successful open has a new kernel open description. */
int sucrune_pty_session_open(struct sucrune_pty_table *, const struct sucrune_fd_table *,
                            int broker, uint64_t guest_flags);
/* Caller owns the returned nonblocking private FD until close. Use only to
 * observe readiness on this exact owned controlling terminal. Never put this
 * substitute FD in the original guest OFD or use it for guest reads/writes.
 * Without a controlling terminal use the broker's actual PTY_POLL. */
int sucrune_pty_session_poll_fd(int broker, int token);
/* scalar is used only for TIOCSCTTY, which accepts zero (no stealing).
 * group_or_sid is bounded host memory, never a guest pointer. For TIOCSPGRP
 * the process registry pins the selected group through the ioctl. */
int sucrune_pty_session_control(int broker, int token, uint64_t command,
                               uint64_t scalar, int *group_or_sid, struct sucrune_process_group *processes);
#endif
