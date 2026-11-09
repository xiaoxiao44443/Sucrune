#include "pty_child.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
#endif

#define RAW_FN __attribute__((no_stack_protector))
#define RAW(n,a,b,c,d) ops->raw((n),(long)(a),(long)(b),(long)(c),(long)(d),0L,0L)

static RAW_FN int ready(const struct sucrune_pty_child_ops *ops) {
    return ops != NULL && ops->raw != NULL && ops->lookup != NULL && ops->publish != NULL && ops->copy != NULL;
}

static RAW_FN long publish(const struct sucrune_pty_child_ops *ops, long fd,
                           enum sucrune_pty_kind kind, int number, uint64_t flags) {
    if (fd < 0) return fd;
    int result = ops->publish(ops->context, (int)fd, kind, number, flags);
    if (result < 0) (void)RAW(SYS_close, fd, 0, 0, 0);
    return result;
}

static RAW_FN long peer(const struct sucrune_pty_child_ops *ops, const struct sucrune_pty_endpoint *master,
                        uint64_t guest_flags) {
    int flags;
    int error = sucrune_pty_open_flags(guest_flags, &flags);
    if (error != 0) return error;
    long fd = RAW(SYS_ioctl, master->fd, TIOCGPTPEER, flags & ~O_NOFOLLOW, 0);
    return publish(ops, fd, SUCRUNE_PTY_SLAVE, master->number, guest_flags);
}

RAW_FN long sucrune_pty_child_ioctl(const struct sucrune_pty_child_ops *ops, unsigned int guestfd,
                                    uint64_t command, uint64_t argument) {
    if (!ready(ops)) return -EINVAL;
    struct sucrune_pty_endpoint entry;
    int error = ops->lookup(ops->context, guestfd, &entry);
    if (error != 0) return error;
    struct sucrune_pty_request plan;
    error = sucrune_pty_plan(entry.kind, command, &plan);
    if (error != 0) return error;
    if (plan.argument == SUCRUNE_PTY_OPEN_PEER) return peer(ops, &entry, argument);
    if (plan.argument == SUCRUNE_PTY_SCALAR) {
        if (command == TIOCSCTTY && (entry.kind != SUCRUNE_PTY_SLAVE || argument != 0U)) return -EPERM;
        if (command == TCFLSH && argument > 2U) return -EINVAL;
        return RAW(SYS_ioctl, entry.fd, command, argument, 0);
    }
    union { int value; uint8_t bytes[SUCRUNE_PTY_BUFFER]; } data;
    if (plan.size > sizeof(data)) return -EOVERFLOW;
    if (plan.argument == SUCRUNE_PTY_GET) {
        for (size_t i = 0; i < plan.size; ++i) ((volatile uint8_t *)data.bytes)[i] = 0;
    } else {
        error = ops->copy(ops->context, (uintptr_t)argument, data.bytes, plan.size, 0);
        if (error != 0) return error;
    }
    if (plan.argument == SUCRUNE_PTY_SET_GROUP) {
        if (data.value <= 0) return -EINVAL;
        if (ops->allow_group == NULL || !ops->allow_group(ops->context, data.value)) return -EPERM;
    }
    long rc = RAW(SYS_ioctl, entry.fd, command, &data, 0);
    if (rc < 0 || plan.argument != SUCRUNE_PTY_GET) return rc;
    return ops->copy(ops->context, (uintptr_t)argument, data.bytes, plan.size, 1);
}

/* Explicit volatile comparisons keep the raw continuation independent of
 * libc memcmp/strlen, even with the release optimizer enabled. */
static RAW_FN int exact(const volatile char *p, const volatile char *expected) {
    for (; *expected != '\0'; ++p, ++expected) if (*p != *expected) return 0;
    return *p == '\0';
}

static RAW_FN int pts_number(const volatile char *p) {
    const volatile char *prefix = "/dev/pts/";
    for (; *prefix != '\0'; ++p, ++prefix) if (*p != *prefix) return -1;
    if (*p == '\0' || (*p == '0' && p[1] != '\0')) return -1;
    int number = 0;
    for (; *p != '\0'; ++p) {
        int digit = *p - '0';
        if (digit < 0 || digit > 9 || number > (INT_MAX - digit) / 10) return -1;
        number = number * 10 + digit;
    }
    return number;
}

RAW_FN long sucrune_pty_child_open(const struct sucrune_pty_child_ops *ops, const char *path, uint64_t guest_flags) {
    if (!ready(ops) || path == NULL) return -EINVAL;
    int flags;
    int error = sucrune_pty_open_flags(guest_flags, &flags);
    if (error != 0) return error;
    if (exact(path, "/dev/ptmx")) {
        long fd = RAW(SYS_openat, AT_FDCWD, "/dev/ptmx", flags | O_NOCTTY, 0);
        if (fd < 0) return fd;
        int number = -1;
        long rc = RAW(SYS_ioctl, fd, TIOCGPTN, &number, 0);
        if (rc < 0 || number < 0) { (void)RAW(SYS_close, fd, 0, 0, 0); return rc < 0 ? rc : -EIO; }
        return publish(ops, fd, SUCRUNE_PTY_MASTER, number, guest_flags);
    }
    int controlling = exact(path, "/dev/tty");
    int number = controlling ? -1 : pts_number(path);
    if (!controlling && number < 0) return -ENOENT;
    long sid = controlling ? RAW(SYS_getsid, 0, 0, 0, 0) : 0;
    if (sid < 0) return sid;
    for (unsigned int gfd = 0; gfd < SUCRUNE_PTY_ENDPOINTS; ++gfd) {
        struct sucrune_pty_endpoint entry;
        if (ops->lookup(ops->context, gfd, &entry) != 0 || entry.kind == SUCRUNE_PTY_NONE) continue;
        if (controlling) {
            int owner = 0;
            if (RAW(SYS_ioctl, entry.fd, TIOCGSID, &owner, 0) < 0 || owner != sid) continue;
            long fd = RAW(SYS_openat, AT_FDCWD, "/dev/tty", flags | O_NOCTTY, 0);
            return publish(ops, fd, SUCRUNE_PTY_SLAVE, entry.number, guest_flags);
        }
        if (entry.kind == SUCRUNE_PTY_MASTER && entry.number == number) return peer(ops, &entry, guest_flags);
    }
    return controlling ? -ENXIO : -ENOENT;
}

RAW_FN long sucrune_pty_child_setsid(const struct sucrune_pty_child_ops *ops) {
    if (ops == NULL || ops->raw == NULL) return -EINVAL;
    return RAW(SYS_setsid, 0, 0, 0, 0);
}
