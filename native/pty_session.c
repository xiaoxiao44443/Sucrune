#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "pty_session.h"
#include "guest_processes.h"
#include "broker_transport.h"
#include "pty_broker.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int control_master(int broker, int token, int *number) {
    if (!sucrune_pty_slave_handle(token)) return -EBADF;
    struct sucrune_request request = {.magic = SUCRUNE_BROKER_MAGIC, .operation = SUCRUNE_PTY_CONTROL_MASTER,
        .args = {token, 0, 0, 0}};
    struct sucrune_response response;
    int fd = -1;
    int rc = sucrune_broker_exchange(broker, &request, &response, &fd, 2000);
    if (rc != 0) return rc;
    if (response.result < 0) return (int)response.result;
    if (fd < 0 || response.result > INT_MAX || response.size != 0) {
        if (fd >= 0) (void)close(fd);
        return -EPROTO;
    }
    /* broker_transport has checked the real right's chr type, CLOEXEC and
     * TIOCGPTN against response.result. It never accepts a slave right. */
    *number = (int)response.result;
    return fd;
}

static int same_session(int master) {
    int owner = 0;
    pid_t self = getsid(0);
    if (self < 0 || ioctl(master, TIOCGSID, &owner) < 0) return -errno;
    return owner > 0 && owner == self ? 0 : -ENXIO;
}

static int alias(int broker, int token, uint64_t flags, int *number) {
    int physical;
    int rc = sucrune_pty_open_flags(flags, &physical);
    if (rc != 0) return rc;
    int master = control_master(broker, token, number);
    if (master < 0) return master;
    int fd = -1;
    rc = same_session(master);
    if (rc == 0) {
        /* A session has one controlling terminal. Open its kernel alias only
         * after verifying this trusted master is attached to our own SID. */
        fd = open("/dev/tty", physical | O_NOCTTY);
        if (fd < 0) rc = -errno;
    }
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) < 0) rc = -errno;
        else if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 5U || minor(st.st_rdev) != 0U) rc = -ENODEV;
        if (rc == 0) {
            int alias_sid = 0;
            if (ioctl(fd, TIOCGSID, &alias_sid) == 0) {
                if (alias_sid != getsid(0)) rc = -ENXIO;
            } else if (errno != EACCES && errno != EPERM) rc = -errno;
        }
        /* Device ioctl allowlists can deny TIOCGSID on the alias while
         * allowing it on the master. Recheck the owned session after open;
         * the alias was freshly opened by this process, never imported. */
        if (rc == 0) rc = same_session(master);
    }
    (void)close(master);
    if (rc != 0) { if (fd >= 0) (void)close(fd); return rc; }
    return fd;
}

int sucrune_pty_session_poll_fd(int broker, int token) {
    int number;
    return alias(broker, token, O_RDWR | O_NONBLOCK | O_NOCTTY, &number);
}

int sucrune_pty_session_open(struct sucrune_pty_table *ptys, const struct sucrune_fd_table *files,
                            int broker, uint64_t guest_flags) {
    if (ptys == NULL || files == NULL) return -EINVAL;
    int flags;
    if (sucrune_pty_open_flags(guest_flags, &flags) != 0) return -EINVAL;
    size_t slot = 0;
    while (slot < SUCRUNE_PTY_ENDPOINTS && ptys->entries[slot].kind != SUCRUNE_PTY_NONE) ++slot;
    if (slot == SUCRUNE_PTY_ENDPOINTS) return -EMFILE;
    for (size_t i = 0; i < files->limit; ++i) {
        const struct sucrune_fd_resource *r = &files->resources[i];
        if (r->kind != SUCRUNE_FD_BROKER || r->references == 0 || !sucrune_pty_slave_handle(r->handle)) continue;
        int number;
        int fd = alias(broker, r->handle, guest_flags, &number);
        if (fd == -ENOTTY || fd == -ENXIO || fd == -EIO) continue;
        if (fd < 0) return fd;
        ptys->entries[slot] = (struct sucrune_pty_endpoint){.fd = fd, .number = number, .kind = SUCRUNE_PTY_SLAVE};
        return fd;
    }
    return -ENXIO;
}

static int readable(int broker, int token) {
    struct sucrune_request req = {.magic = SUCRUNE_BROKER_MAGIC, .operation = 25,
        .args = {token, F_GETFL, 0, 0}};
    struct sucrune_response reply;
    int rc = sucrune_broker_exchange(broker, &req, &reply, NULL, 2000);
    if (rc != 0) return rc;
    if (reply.result < 0) return (int)reply.result;
    if (reply.size != 0 || reply.result > INT_MAX) return -EPROTO;
    return ((int)reply.result & O_ACCMODE) == O_WRONLY ? -EPERM : 0;
}

int sucrune_pty_session_control(int broker, int token, uint64_t command,
                               uint64_t scalar, int *group_or_sid, struct sucrune_process_group *processes) {
    if (!sucrune_pty_slave_handle(token)) return -EBADF;
    if (command != TIOCSCTTY && command != TIOCGPGRP && command != TIOCSPGRP && command != TIOCGSID) return -ENOTTY;
    if (command != TIOCSCTTY && group_or_sid == NULL) return -EINVAL;
    if (scalar != 0U) return command == TIOCSCTTY ? -EPERM : -EINVAL;
    int rc;
    if (command == TIOCSPGRP && *group_or_sid <= 0) return -EINVAL;
    if (command == TIOCSCTTY) {
        rc = readable(broker, token);
        if (rc != 0) return rc;
    }
    int number;
    int master = control_master(broker, token, &number);
    if (master < 0) return master;
    if (command == TIOCSCTTY) rc = ioctl(master, TIOCSCTTY, 0) < 0 ? -errno : 0;
    else {
        rc = same_session(master);
        if (rc == -ENXIO) rc = -ENOTTY;
        if (rc == 0 && command == TIOCSPGRP) rc = sucrune_processes_set_foreground(processes,master,*group_or_sid);
        else if (rc == 0) rc = ioctl(master, (unsigned int)command, group_or_sid) < 0 ? -errno : 0;
    }
    (void)close(master);
    return rc;
}
