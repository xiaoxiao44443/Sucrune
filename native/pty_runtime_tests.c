#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "pty_runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
#endif

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "PTY check %u line %d failed: %s (errno=%d)\n", checks, __LINE__, #x, errno); return 1; } } while (0)

static int plan_tests(void) {
    struct sucrune_pty_request p = {0};
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_MASTER, TCGETS, &p) == 0 &&
          p.argument == SUCRUNE_PTY_GET && p.size == 36U && !p.may_wait);
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_SLAVE, TCSETSF, &p) == 0 &&
          p.argument == SUCRUNE_PTY_SET && p.size == 36U && p.may_wait);
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_MASTER, TIOCGPTPEER, &p) == 0 && p.argument == SUCRUNE_PTY_OPEN_PEER);
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_SLAVE, TIOCGPTPEER, &p) == -ENOTTY);
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_NONE, TCGETS, &p) == -ENOTTY);
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_MASTER, (UINT64_C(1) << 32) | TCGETS, &p) == -ENOTTY);
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_SLAVE, TIOCSTI, &p) == -ENOTTY);
    CHECK(sucrune_pty_plan(SUCRUNE_PTY_SLAVE, TIOCSETD, &p) == -ENOTTY);
    CHECK(sucrune_pty_path("/dev/ptmx") && sucrune_pty_path("/dev/tty") && sucrune_pty_path("/dev/pts/10"));
    CHECK(!sucrune_pty_path("/dev/ptmx-other") && !sucrune_pty_path("dev/tty") && !sucrune_pty_path("/proc/self/fd/0"));
    struct sucrune_pty_table empty;
    sucrune_pty_init(&empty);
    CHECK(sucrune_pty_open(&empty, "/dev/pts/1", O_RDWR) == -ENOENT);
    CHECK(sucrune_pty_open(&empty, "/dev/pts/../tty", O_RDWR) == -ENOENT);
    CHECK(sucrune_pty_open(&empty, "/dev/pts/00", O_RDWR) == -ENOENT);
    CHECK(sucrune_pty_open(&empty, "/dev/pts/2147483648", O_RDWR) == -ENOENT);
    CHECK(sucrune_pty_open(&empty, "/dev/tty", O_RDWR) == -ENXIO);
    CHECK(sucrune_pty_open(&empty, "/dev/ptmx", O_RDWR | O_CREAT) == -EINVAL);
    CHECK(sucrune_pty_open(&empty, "/dev/ptmx", UINT64_C(1) << 40) == -EINVAL);
    CHECK(sucrune_pty_peer(&empty, 0, O_RDWR) == -EBADF && sucrune_pty_release(&empty, 0) == -EBADF);
    return 0;
}

static int exchange(int write_fd, int read_fd, const void *data, size_t length) {
    if (length > 16U || write(write_fd, data, length) != (ssize_t)length) return 0;
    unsigned char received[16];
    size_t done = 0;
    while (done < length) {
        struct pollfd pollfd = { .fd = read_fd, .events = POLLIN };
        if (poll(&pollfd, 1U, 1000) != 1) return 0;
        ssize_t result = read(read_fd, received + done, length - done);
        if (result <= 0) return 0;
        done += (size_t)result;
    }
    return memcmp(received, data, length) == 0;
}

static int control_child(struct sucrune_pty_table *t, int master, int slave) {
    CHECK(sucrune_pty_release(t, master) == 0);
    CHECK(setsid() == getpid());
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TIOCSCTTY, 1U, NULL, 0U, 0) == -EPERM);
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TIOCSCTTY, 0U, NULL, 0U, 0) == 0);
    int sid = 0, pg = 0;
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TIOCGSID, 0U, &sid, sizeof(sid), 0) == 0 && sid == getpid());
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TIOCGPGRP, 0U, &pg, sizeof(pg), 0) == 0 && pg == getpid());
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TIOCSPGRP, 0U, &pg, sizeof(pg), 0) == -EPERM);
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TIOCSPGRP, 0U, &pg, sizeof(pg), pg) == 0);
    int tty = sucrune_pty_open(t, "/dev/tty", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0 && sucrune_pty_kind(t, tty) == SUCRUNE_PTY_SLAVE);
    CHECK(sucrune_pty_release(t, tty) == 0 && sucrune_pty_release(t, slave) == 0);
    return 0;
}

static int kernel_tests(void) {
    struct sucrune_pty_table t, foreign;
    sucrune_pty_init(&t); sucrune_pty_init(&foreign);
    int master = sucrune_pty_open(&t, "/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master < 0) { fprintf(stderr, "direct master open errno=%d\n", -master); return 1; }
    CHECK(sucrune_pty_kind(&t, master) == SUCRUNE_PTY_MASTER && sucrune_pty_kind(&foreign, master) == SUCRUNE_PTY_NONE);
    CHECK((fcntl(master, F_GETFD) & FD_CLOEXEC) != 0 && (fcntl(master, F_GETFL) & O_NONBLOCK) != 0);
    int number = -1;
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_MASTER, master, TIOCGPTN, 0U, &number, sizeof(number), 0) == 0 && number >= 0);
    CHECK(sucrune_pty_peer(&t, master, O_RDWR | O_NOCTTY) < 0);
    int unlock = 0;
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_MASTER, master, TIOCSPTLCK, 0U, &unlock, sizeof(unlock), 0) == 0);
    int slave = sucrune_pty_peer(&t, master, O_RDWR | O_NOCTTY | O_NONBLOCK);
    CHECK(slave >= 0 && sucrune_pty_kind(&t, slave) == SUCRUNE_PTY_SLAVE);
    char path[64];
    CHECK(snprintf(path, sizeof(path), "/dev/pts/%d", number) > 0);
    CHECK(sucrune_pty_open(&foreign, path, O_RDWR) == -ENOENT);
    int reopened = sucrune_pty_open(&t, path, O_RDONLY | O_NOCTTY);
    CHECK(reopened >= 0 && (fcntl(reopened, F_GETFL) & O_ACCMODE) == O_RDONLY);
    struct stat a, b;
    CHECK(fstat(reopened, &a) == 0 && fstat(slave, &b) == 0 && S_ISCHR(a.st_mode) &&
          a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_rdev == b.st_rdev);
    CHECK(sucrune_pty_release(&t, reopened) == 0 && sucrune_pty_kind(&t, reopened) == SUCRUNE_PTY_NONE);
    CHECK(sucrune_pty_release(&t, reopened) == -EBADF);
    unsigned char term[SUCRUNE_PTY_BUFFER] = {0};
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TCGETS, 0, term, sizeof(term) - 1U, 0) == -EINVAL);
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TCGETS, 0, term, sizeof(term), 0) == 0);
    struct termios raw;
    CHECK(tcgetattr(slave, &raw) == 0);
    cfmakeraw(&raw);
    /* Obtain the kernel layout after setting raw defaults, then restore it
     * through the tested bounded transport (glibc struct termios is larger). */
    CHECK(tcsetattr(slave, TCSANOW, &raw) == 0 && ioctl(slave, TCGETS, term) == 0);
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TCSETSF, 0, term, sizeof(term), 0) == 0);
    struct winsize win = { .ws_row = 39, .ws_col = 103 }, seen = {0};
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_MASTER, master, TIOCSWINSZ, 0, &win, sizeof(win), 0) == 0);
    CHECK(sucrune_pty_apply(SUCRUNE_PTY_SLAVE, slave, TIOCGWINSZ, 0, &seen, sizeof(seen), 0) == 0 &&
          seen.ws_row == 39 && seen.ws_col == 103);
    CHECK(exchange(master, slave, "\0\r\n\xff", 4U));
    CHECK(exchange(slave, master, "\xff\n\r\0", 4U));
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(control_child(&t, master, slave));
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(sucrune_pty_release(&t, slave) == 0);
    struct pollfd wait = { .fd = master, .events = POLLIN };
    CHECK(poll(&wait, 1U, 1000) == 1 && (wait.revents & POLLHUP));
    CHECK(sucrune_pty_release(&t, master) == 0 && sucrune_pty_kind(&t, master) == SUCRUNE_PTY_NONE);
    CHECK(sucrune_pty_open(&t, path, O_RDWR) == -ENOENT);
    return 0;
}

int main(void) {
    if (plan_tests() != 0 || kernel_tests() != 0) return 1;
    printf("PASS %u parent checks plus child setsid/CTTY/pgrp/dev-tty checks\n", checks);
    return 0;
}
