#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "pty_broker.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
#endif

/* Slaves refer weakly to the open master so possession of a slave never
 * delays master hangup. A private temporary dup pins a checked control call. */
struct terminal {
    atomic_uint refs;
    pthread_mutex_t lock;
    int master;
};
struct sucrune_pty_ofd {
    atomic_uint refs;
    atomic_int guest_flags;
    int fd, number;
    enum sucrune_pty_kind kind;
    struct terminal *tty;
};

static void drop(struct sucrune_pty_broker *b, size_t i) {
    struct sucrune_pty_ofd *ofd = b->slots[i];
    b->slots[i] = NULL;
    b->exec_flags[i] = 0;
    if (ofd != NULL && atomic_fetch_sub_explicit(&ofd->refs, 1U, memory_order_acq_rel) == 1U) {
        if (ofd->kind == SUCRUNE_PTY_MASTER) {
            (void)pthread_mutex_lock(&ofd->tty->lock);
            ofd->tty->master = -1;
            (void)pthread_mutex_unlock(&ofd->tty->lock);
        }
        (void)close(ofd->fd);
        if (atomic_fetch_sub_explicit(&ofd->tty->refs, 1U, memory_order_acq_rel) == 1U) {
            (void)pthread_mutex_destroy(&ofd->tty->lock);
            free(ofd->tty);
        }
        free(ofd);
    }
}

void sucrune_pty_broker_fork(struct sucrune_pty_broker *child, const struct sucrune_pty_broker *parent) {
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i) {
        child->slots[i] = parent->slots[i];
        child->exec_flags[i] = parent->exec_flags[i];
        if (child->slots[i] != NULL) (void)atomic_fetch_add_explicit(&child->slots[i]->refs, 1U, memory_order_relaxed);
    }
}

void sucrune_pty_broker_destroy(struct sucrune_pty_broker *b) {
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i) drop(b, i);
}

void sucrune_pty_broker_exec(struct sucrune_pty_broker *b) {
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i)
        if (b->exec_flags[i] != 0U) drop(b, i);
}

int sucrune_pty_broker_claims(const struct sucrune_request *r) {
    if (r->operation >= SUCRUNE_PTY_MASTER_OPEN && r->operation <= SUCRUNE_PTY_CONTROL_MASTER) return 1;
    if (!sucrune_pty_slave_handle(r->args[0])) return 0;
    switch (r->operation) {
    case 25: case 57: case 63: case 64: case 80: return 1;
    default: return 0;
    }
}

static int master_slot(struct sucrune_pty_broker *b, int64_t number) {
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i) {
        struct sucrune_pty_ofd *ofd = b->slots[i];
        if (ofd != NULL && ofd->kind == SUCRUNE_PTY_MASTER && ofd->number == number) return (int)i;
    }
    return -ENOENT;
}

static int create(struct sucrune_pty_broker *b, const struct sucrune_request *r, int *right) {
    int master = r->operation == SUCRUNE_PTY_MASTER_OPEN;
    uint64_t guest_flags = (uint64_t)r->args[master ? 0 : 1];
    int flags;
    int error = sucrune_pty_open_flags(guest_flags, &flags);
    if (error != 0 || r->size || r->args[2] || r->args[3] || (master && r->args[1])) return -EINVAL;
    size_t i = 0;
    while (i < SUCRUNE_PTY_ENDPOINTS && b->slots[i] != NULL) ++i;
    if (i == SUCRUNE_PTY_ENDPOINTS) return -EMFILE;
    int fd = -1, number = -1;
    struct terminal *tty = NULL;
    if (master) {
        fd = open("/dev/ptmx", flags | O_NOCTTY);
        if (fd < 0) return -errno;
        if (ioctl(fd, TIOCGPTN, &number) < 0) { error = -errno; (void)close(fd); return error; }
    } else {
        int source = master_slot(b, r->args[0]);
        if (source < 0) return source;
        number = b->slots[source]->number;
        tty = b->slots[source]->tty;
        fd = ioctl(b->slots[source]->fd, TIOCGPTPEER, (flags & ~O_NOFOLLOW) | O_NONBLOCK | O_NOCTTY);
        if (fd < 0) return -errno;
    }
    struct sucrune_pty_ofd *ofd = calloc(1U, sizeof(*ofd));
    if (ofd == NULL) { (void)close(fd); return -ENOMEM; }
    if (master) {
        tty = malloc(sizeof(*tty));
        if (tty == NULL) { free(ofd); (void)close(fd); return -ENOMEM; }
        int rc = pthread_mutex_init(&tty->lock, NULL);
        if (rc != 0) { free(tty); free(ofd); (void)close(fd); return -rc; }
        tty->master = fd;
        atomic_init(&tty->refs, 1U);
    } else (void)atomic_fetch_add_explicit(&tty->refs, 1U, memory_order_relaxed);
    ofd->tty = tty;
    atomic_init(&ofd->refs, 1U);
    atomic_init(&ofd->guest_flags, (int)guest_flags & (O_ACCMODE | O_NONBLOCK | O_LARGEFILE));
    ofd->fd = fd; ofd->number = number; ofd->kind = master ? SUCRUNE_PTY_MASTER : SUCRUNE_PTY_SLAVE;
    b->slots[i] = ofd;
    if (master) { *right = fd; return number; }
    return (int)i + SUCRUNE_PTY_HANDLE_BASE;
}

static int control(struct sucrune_pty_ofd *ofd, const struct sucrune_request *r, struct sucrune_response *out) {
    uint64_t command = (uint64_t)r->args[1];
    struct sucrune_pty_request p;
    int error = sucrune_pty_plan(SUCRUNE_PTY_SLAVE, command, &p);
    if (r->args[3]) return -EINVAL;
    if (error != 0) return error;
    /* Never change the Android manager's controlling terminal or foreground
     * process group. A guest process-session operation is a distinct capability. */
    if (command == TIOCSCTTY || command == TIOCGSID || command == TIOCGPGRP || command == TIOCSPGRP) return -ENOTSUP;
    if (p.argument != SUCRUNE_PTY_SCALAR && r->args[2]) return -EINVAL;
    if (r->size != (p.argument == SUCRUNE_PTY_SET ? p.size : 0U)) return -EINVAL;
    union { uint32_t alignment; unsigned char data[SUCRUNE_PTY_BUFFER]; } local = {0};
    if (p.argument == SUCRUNE_PTY_SET) memcpy(local.data, r->data, p.size);
    error = sucrune_pty_apply(SUCRUNE_PTY_SLAVE, ofd->fd, command,
        (uint64_t)r->args[2], local.data, p.size, 0);
    if (error == 0 && p.argument == SUCRUNE_PTY_GET) {
        memcpy(out->data, local.data, p.size);
        out->size = (uint32_t)p.size;
    }
    return error;
}

static int64_t operation(struct sucrune_pty_broker *b, const struct sucrune_request *r,
                         struct sucrune_response *out, int *right, sucrune_pty_stat_reply status) {
    if (r->reserved != 0U || r->size > SUCRUNE_IO_LIMIT) return -EINVAL;
    if (r->operation == SUCRUNE_PTY_MASTER_OPEN || r->operation == SUCRUNE_PTY_SLAVE_OPEN) return create(b, r, right);
    if (r->operation == SUCRUNE_PTY_MASTER_DROP || r->operation == SUCRUNE_PTY_MASTER_EXEC) {
        if (r->args[2] || r->args[3] || r->size || (r->args[1] != 0 &&
                (r->operation == SUCRUNE_PTY_MASTER_DROP || r->args[1] != FD_CLOEXEC))) return -EINVAL;
        int slot = master_slot(b, r->args[0]);
        if (slot < 0) return slot;
        if (r->operation == SUCRUNE_PTY_MASTER_DROP) drop(b, (size_t)slot);
        else b->exec_flags[slot] = (unsigned char)r->args[1];
        return 0;
    }
    if (!sucrune_pty_slave_handle(r->args[0])) return -EBADF;
    size_t slot = (size_t)(r->args[0] - SUCRUNE_PTY_HANDLE_BASE);
    struct sucrune_pty_ofd *ofd = b->slots[slot];
    if (ofd == NULL || ofd->kind != SUCRUNE_PTY_SLAVE) return -EBADF;
    switch (r->operation) {
    case SUCRUNE_PTY_CONTROL_MASTER: {
        if (r->args[1] || r->args[2] || r->args[3] || r->size) return -EINVAL;
        (void)pthread_mutex_lock(&ofd->tty->lock);
        int fd = ofd->tty->master < 0 ? -1 : fcntl(ofd->tty->master, F_DUPFD_CLOEXEC, 3);
        int rc = ofd->tty->master < 0 ? -EIO : fd < 0 ? -errno : ofd->number;
        (void)pthread_mutex_unlock(&ofd->tty->lock);
        *right = fd; /* caller closes this owned temporary right after send */
        return rc;
    }
    case SUCRUNE_PTY_DESCRIBE:
        return r->args[1] || r->args[2] || r->args[3] || r->size ? -EINVAL : ofd->number;
    case SUCRUNE_PTY_IOCTL: return control(ofd, r, out);
    case SUCRUNE_PTY_POLL: {
        const int allowed = POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLWRNORM;
        if (r->size || r->args[2] || r->args[3] || r->args[1] < 0 || (r->args[1] & ~((int64_t)allowed))) return -EINVAL;
        struct pollfd p = {.fd = ofd->fd, .events = (short)r->args[1]};
        return poll(&p, 1U, 0) < 0 ? -errno : p.revents;
    }
    case 57:
        if (r->args[1] || r->args[2] || r->args[3] || r->size) return -EINVAL;
        drop(b, slot);
        return 0;
    case 80: {
        if (r->args[1] || r->args[2] || r->args[3] || r->size || status == NULL) return -EINVAL;
        struct stat st;
        if (fstat(ofd->fd, &st) < 0) return -errno;
        status(out, &st);
        return 0;
    }
    case 25: {
        if (r->size || r->args[3]) return -EINVAL;
        int flags = atomic_load_explicit(&ofd->guest_flags, memory_order_acquire);
        if (r->args[1] == F_GETFD) return b->exec_flags[slot];
        if (r->args[1] == F_SETFD) {
            if (r->args[2] != 0 && r->args[2] != FD_CLOEXEC) return -EINVAL;
            b->exec_flags[slot] = (unsigned char)r->args[2];
            return 0;
        }
        if (r->args[1] == F_GETFL) return flags;
        const int allowed = O_ACCMODE | O_NONBLOCK | O_LARGEFILE | O_CLOEXEC | O_NOCTTY;
        if (r->args[1] != F_SETFL || r->args[2] < 0 || (r->args[2] & ~((int64_t)allowed))) return -EINVAL;
        atomic_store_explicit(&ofd->guest_flags, (flags & ~O_NONBLOCK) | ((int)r->args[2] & O_NONBLOCK), memory_order_release);
        return 0;
    }
    case 63: case 64: {
        int writing = r->operation == 64U;
        if (r->args[2] || r->args[3] || r->args[1] < 0 || r->args[1] > SUCRUNE_IO_LIMIT ||
            r->size != (writing ? (uint32_t)r->args[1] : 0U)) return -EINVAL;
        size_t length = (size_t)r->args[1];
        ssize_t n = writing ? write(ofd->fd, r->data, length) : read(ofd->fd, out->data, length);
        if (n < 0) return -errno;
        if (!writing) out->size = (uint32_t)n;
        return n;
    }
    default: return -ENOTSUP;
    }
}

void sucrune_pty_broker_dispatch(struct sucrune_pty_broker *b, const struct sucrune_request *r,
                                 struct sucrune_response *out, int *right, sucrune_pty_stat_reply status) {
    out->magic = SUCRUNE_BROKER_MAGIC; out->size = 0; *right = -1;
    out->result = operation(b, r, out, right, status);
}
