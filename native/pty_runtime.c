#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "pty_runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
#endif
#ifndef TIOCGPTLCK
#define TIOCGPTLCK _IOR('T', 0x39, int)
#endif

/* Both supported Linux/Android ABIs use the asm-generic kernel termios, not
 * the larger glibc user-space tcgetattr() representation. */
struct kernel_termios { uint32_t flags[4]; uint8_t line, cc[19]; };
_Static_assert(sizeof(struct kernel_termios) == SUCRUNE_PTY_BUFFER, "Linux termios ABI");
_Static_assert(sizeof(struct winsize) == 8, "Linux winsize ABI");
_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4, "Linux terminal PID ABI");

void sucrune_pty_init(struct sucrune_pty_table *table) {
    if (table != NULL) memset(table, 0, sizeof(*table));
}

static struct sucrune_pty_endpoint *unused(struct sucrune_pty_table *table) {
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i)
        if (table->entries[i].kind == SUCRUNE_PTY_NONE) return &table->entries[i];
    return NULL;
}

static const struct sucrune_pty_endpoint *endpoint(const struct sucrune_pty_table *table, int fd) {
    if (table == NULL || fd < 0) return NULL;
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i)
        if (table->entries[i].kind != SUCRUNE_PTY_NONE && table->entries[i].fd == fd) return &table->entries[i];
    return NULL;
}

enum sucrune_pty_kind sucrune_pty_kind(const struct sucrune_pty_table *table, int fd) {
    const struct sucrune_pty_endpoint *entry = endpoint(table, fd);
    return entry == NULL ? SUCRUNE_PTY_NONE : entry->kind;
}

int sucrune_pty_number(const struct sucrune_pty_table *table, int fd) {
    const struct sucrune_pty_endpoint *entry = endpoint(table, fd);
    return entry == NULL ? -EBADF : entry->number;
}

static int slave_identity(dev_t device, int number) {
    /* Modern devpts uses major 136 with the index in its extended minor.
     * The historical contiguous 136..143 ranges use 256 minors per major. */
    unsigned int device_major = major(device), device_minor = minor(device);
    if (device_major < 136U || device_major > 143U || (device_major != 136U && device_minor >= 256U)) return 0;
    return (device_major - 136U) * 256U + device_minor == (unsigned int)number;
}

int sucrune_pty_adopt(struct sucrune_pty_table *table, int fd, enum sucrune_pty_kind kind, int number) {
    if (table == NULL || number < 0 || (kind != SUCRUNE_PTY_MASTER && kind != SUCRUNE_PTY_SLAVE)) return -EINVAL;
    if (fd < 0) return -EBADF;
    if (endpoint(table, fd) != NULL) return -EEXIST;
    struct sucrune_pty_endpoint *slot = unused(table);
    if (slot == NULL) return -EMFILE;
    struct stat st;
    if (fstat(fd, &st) < 0) return -errno;
    if (!S_ISCHR(st.st_mode)) return -ENOTTY;
    if (kind == SUCRUNE_PTY_MASTER) {
        int actual = -1;
        if (ioctl(fd, TIOCGPTN, &actual) < 0) return -errno;
        if (actual != number) return -ENODEV;
    } else if (!slave_identity(st.st_rdev, number)) {
        /* An owned /dev/tty alias reports 5:0. Resolve its actual terminal.
         * Reject all other device classes, including ptmx (5:2). */
        if (major(st.st_rdev) != 5U || minor(st.st_rdev) != 0U) return -ENODEV;
        unsigned int real_device = 0U;
        if (ioctl(fd, TIOCGDEV, &real_device) < 0) return -errno;
        if (!slave_identity((dev_t)real_device, number)) return -ENODEV;
    }
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || ((flags & FD_CLOEXEC) == 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)) return -errno;
    *slot = (struct sucrune_pty_endpoint){ .fd = fd, .number = number, .kind = kind };
    return 0;
}

int sucrune_pty_path(const char *path) {
    if (path == NULL) return 0;
    return strcmp(path, "/dev/ptmx") == 0 || strcmp(path, "/dev/tty") == 0 || strncmp(path, "/dev/pts/", 9U) == 0;
}

static int parse_number(const char *text) {
    int value = 0;
    if (*text == '\0' || (*text == '0' && text[1] != '\0')) return -1;
    for (; *text != '\0'; ++text) {
        if (*text < '0' || *text > '9') return -1;
        int digit = *text - '0';
        if (value > (INT_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
    }
    return value;
}

int sucrune_pty_open_flags(uint64_t guest_flags, int *flags) {
    const unsigned int allowed = O_ACCMODE | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | O_LARGEFILE | O_NOFOLLOW;
    if (flags == NULL || (guest_flags & ~(uint64_t)allowed) != 0U || (guest_flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    *flags = (int)guest_flags | O_CLOEXEC;
    return 0;
}

static int register_fd(struct sucrune_pty_endpoint *slot, int fd, int number, enum sucrune_pty_kind kind) {
    struct stat st;
    int error = fstat(fd, &st) < 0 ? errno : 0;
    if (error == 0 && !S_ISCHR(st.st_mode)) error = ENOTTY;
    if (error != 0) { (void)close(fd); return -error; }
    *slot = (struct sucrune_pty_endpoint){ .fd = fd, .number = number, .kind = kind };
    return fd;
}

int sucrune_pty_peer(struct sucrune_pty_table *table, int master, uint64_t guest_flags) {
    const struct sucrune_pty_endpoint *source = endpoint(table, master);
    if (source == NULL) return -EBADF;
    if (source->kind != SUCRUNE_PTY_MASTER) return -ENOTTY;
    int flags, error = sucrune_pty_open_flags(guest_flags, &flags);
    if (error != 0) return error;
    struct sucrune_pty_endpoint *slot = unused(table);
    if (slot == NULL) return -EMFILE;
    /* This opens the exact peer of an owned master in its devpts instance.
     * Never construct a host /dev/pts path from a guest-provided number. */
    int fd = ioctl(master, TIOCGPTPEER, flags & ~O_NOFOLLOW);
    if (fd < 0) return -errno;
    return register_fd(slot, fd, source->number, SUCRUNE_PTY_SLAVE);
}

int sucrune_pty_open(struct sucrune_pty_table *table, const char *path, uint64_t guest_flags) {
    if (table == NULL || path == NULL) return -EINVAL;
    int flags, error = sucrune_pty_open_flags(guest_flags, &flags);
    if (error != 0) return error;
    struct sucrune_pty_endpoint *slot = unused(table);
    if (slot == NULL) return -EMFILE;
    if (strcmp(path, "/dev/ptmx") == 0) {
        int fd = open("/dev/ptmx", flags | O_NOCTTY);
        if (fd < 0) return -errno;
        int number = -1;
        error = ioctl(fd, TIOCGPTN, &number) < 0 ? errno : 0;
        if (error != 0 || number < 0) { (void)close(fd); return error == 0 ? -EIO : -error; }
        return register_fd(slot, fd, number, SUCRUNE_PTY_MASTER);
    }
    if (strncmp(path, "/dev/pts/", 9U) == 0) {
        int number = parse_number(path + 9U);
        if (number < 0) return -ENOENT;
        for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i) {
            const struct sucrune_pty_endpoint *entry = &table->entries[i];
            if (entry->kind == SUCRUNE_PTY_MASTER && entry->number == number)
                return sucrune_pty_peer(table, entry->fd, guest_flags);
        }
        return -ENOENT;
    }
    if (strcmp(path, "/dev/tty") == 0) {
        pid_t session = getsid(0);
        if (session < 0) return -errno;
        for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i) {
            const struct sucrune_pty_endpoint *entry = &table->entries[i];
            pid_t owner = 0;
            if (entry->kind == SUCRUNE_PTY_NONE || ioctl(entry->fd, TIOCGSID, &owner) < 0 || owner != session) continue;
            int fd = open("/dev/tty", flags | O_NOCTTY);
            if (fd < 0) return -errno;
            return register_fd(slot, fd, entry->number, SUCRUNE_PTY_SLAVE);
        }
        return -ENXIO;
    }
    return -ENOENT;
}

int sucrune_pty_release(struct sucrune_pty_table *table, int fd) {
    if (table == NULL || fd < 0) return -EBADF;
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i) {
        struct sucrune_pty_endpoint *entry = &table->entries[i];
        if (entry->kind != SUCRUNE_PTY_NONE && entry->fd == fd) {
            *entry = (struct sucrune_pty_endpoint){0};
            return close(fd) == 0 ? 0 : -errno;
        }
    }
    return -EBADF;
}

int sucrune_pty_plan(enum sucrune_pty_kind kind, uint64_t command, struct sucrune_pty_request *plan) {
    if (plan == NULL) return -EINVAL;
    if (kind != SUCRUNE_PTY_MASTER && kind != SUCRUNE_PTY_SLAVE) return -ENOTTY;
    struct sucrune_pty_request p = {0};
    switch (command) {
    case TCGETS: p.argument = SUCRUNE_PTY_GET; p.size = sizeof(struct kernel_termios); break;
    case TCSETS: case TCSETSW: case TCSETSF:
        p.argument = SUCRUNE_PTY_SET; p.size = sizeof(struct kernel_termios); p.may_wait = command != TCSETS; break;
    case TIOCGWINSZ: p.argument = SUCRUNE_PTY_GET; p.size = sizeof(struct winsize); break;
    case TIOCSWINSZ: p.argument = SUCRUNE_PTY_SET; p.size = sizeof(struct winsize); break;
    case TIOCGPTN: case TIOCGPTLCK: case TIOCSPTLCK: case TIOCGPTPEER:
        if (kind != SUCRUNE_PTY_MASTER) return -ENOTTY;
        if (command == TIOCGPTPEER) p.argument = SUCRUNE_PTY_OPEN_PEER;
        else { p.argument = command == TIOCSPTLCK ? SUCRUNE_PTY_SET : SUCRUNE_PTY_GET; p.size = sizeof(int); }
        break;
    case TIOCGSID: case TIOCGPGRP: case FIONREAD: case TIOCOUTQ:
        p.argument = SUCRUNE_PTY_GET; p.size = sizeof(int); break;
    case TIOCSPGRP: p.argument = SUCRUNE_PTY_SET_GROUP; p.size = sizeof(int); break;
    case TIOCSCTTY: case TCFLSH: p.argument = SUCRUNE_PTY_SCALAR; break;
    default: return -ENOTTY;
    }
    *plan = p;
    return 0;
}

int sucrune_pty_apply(enum sucrune_pty_kind kind, int pinned_fd, uint64_t command,
                      uint64_t scalar, void *host_buffer, size_t size, int allowed_group) {
    struct sucrune_pty_request plan;
    int error = sucrune_pty_plan(kind, command, &plan);
    if (error != 0) return error;
    if (pinned_fd < 0) return -EBADF;
    if (size != plan.size || (size != 0U && host_buffer == NULL)) return -EINVAL;
    if (plan.argument == SUCRUNE_PTY_OPEN_PEER) return -EINVAL;
    if (plan.argument == SUCRUNE_PTY_SCALAR) {
        if (command == TIOCSCTTY && (scalar != 0U || kind != SUCRUNE_PTY_SLAVE)) return -EPERM;
        if (command == TCFLSH && scalar > 2U) return -EINVAL;
        return ioctl(pinned_fd, (unsigned int)command, (unsigned long)scalar) < 0 ? -errno : 0;
    }
    if (plan.argument == SUCRUNE_PTY_SET_GROUP) {
        int requested;
        memcpy(&requested, host_buffer, sizeof(requested));
        if (requested <= 0) return -EINVAL;
        if (requested != allowed_group) return -EPERM;
    }
    return ioctl(pinned_fd, (unsigned int)command, host_buffer) < 0 ? -errno : 0;
}
