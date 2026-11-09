#ifndef SUCRUNE_GUEST_LOCAL_IO_H
#define SUCRUNE_GUEST_LOCAL_IO_H

#include <stddef.h>
#include <stdint.h>

#define SUCRUNE_LOCAL_IO_LIMIT 64U
#define SUCRUNE_LOCAL_CLOEXEC 1U

/* Normalized ARM64 Linux ABI buffers, never raw guest pointers. In particular,
 * x86_64's packed host epoll_event is not the ARM64 guest's 16-byte layout. */
struct sucrune_local_event { uint32_t events, padding; uint64_t data; };
struct sucrune_local_pollfd { int32_t fd; int16_t events, revents; };
struct sucrune_local_timespec { int64_t seconds, nanoseconds; };
/* ARM64 libc's fd_set spans 1024 descriptors. */
struct sucrune_local_fdset { uint64_t words[16]; };
_Static_assert(sizeof(struct sucrune_local_event) == 16U, "ARM64 epoll event size");
_Static_assert(offsetof(struct sucrune_local_event, data) == 8U, "ARM64 epoll data offset");
_Static_assert(sizeof(struct sucrune_local_pollfd) == 8U, "Linux pollfd size");
_Static_assert(sizeof(struct sucrune_local_timespec) == 16U, "ARM64 timespec size");

struct sucrune_local_new_fd { int host_fd, status_flags; unsigned int descriptor_flags; };
struct sucrune_local_pin { int host_fd, error; uintptr_t token; };
enum sucrune_local_pin_mode { SUCRUNE_LOCAL_STABLE_CTL, SUCRUNE_LOCAL_RETAINED_WAIT };

/* All callbacks run with host TLS. They return 0 or negative errno.
 * reserve claims count guest slots before any host FD is created. commit is
 * atomic: success consumes the reservation and all host FDs, failure consumes
 * neither and leaves the table unchanged. cancel releases a failed claim.
 *
 * acquire_many success requires a matching release_many even if individual
 * pins contain negative error. A failed group acquire cleans its own state.
 * STABLE_CTL holds one short table lock for the group: successful host FDs are
 * the entry's stable aliases, not temporary dup FDs. RETAINED_WAIT creates
 * retained dup FDs under a short lock, releasing that lock before returning;
 * release closes them. Never hold the table lock across a blocking wait.
 *
 * Each guest dup alias needs a distinct, stable host dup FD for epoll_ctl's
 * (descriptor number, open description) key. Its O_NONBLOCK state is naturally
 * shared by the kernel. Canonical resources alone do not preserve this key.
 * Invalid guest FDs return -EBADF per pin. Unsupported broker resources return
 * -ENOTSUP, never the broker's transport FD. No host FD reaches guest memory. */
struct sucrune_local_io_ops {
    int (*reserve)(void *context, size_t count, uintptr_t *reservation);
    int (*commit)(void *context, uintptr_t reservation, size_t count,
                  const struct sucrune_local_new_fd *descriptors, int32_t *guest_fds);
    void (*cancel)(void *context, uintptr_t reservation);
    int (*acquire_many)(void *context, const int32_t *guest_fds, size_t count,
                        enum sucrune_local_pin_mode mode, struct sucrune_local_pin *pins);
    void (*release_many)(void *context, enum sucrune_local_pin_mode mode,
                         struct sucrune_local_pin *pins, size_t count);
};
struct sucrune_local_io {
    void *context;
    struct sucrune_local_io_ops ops;
    size_t descriptor_limit; /* Zero selects the ordinary profile. */
};
/* A private eventfd can interrupt an epoll sleep for virtual SIGCHLD. This FD
 * is borrowed for the wait and never registered in the guest epoll object. */
int sucrune_local_epoll_interruptible(struct sucrune_local_io *io,int32_t epfd,
    struct sucrune_local_event *events,int max_events,int timeout_ms,
    const uint64_t *signal_mask,size_t sigset_size,int wake_fd);

/* pipe supports O_NONBLOCK|O_CLOEXEC; eventfd additionally EFD_SEMAPHORE.
 * Internal host FDs are always CLOEXEC; guest CLOEXEC is virtual metadata.
 * Output buffers change only on success. Creation returns guest descriptors,
 * or negative errno; pipe returns zero and writes two guest descriptors. */
/* Workspace file/dir handles use the kernel's default poll mask. /dev/null
 * has the same mask and epoll behavior without granting access to the file.
 * O_PATH keeps the native kernel's descriptor lookup rules on each ABI. */
#define SUCRUNE_FILE_POLL_PATH "/dev/null"
int sucrune_local_file_poll_fd(int open_flags);

int sucrune_local_pipe2(struct sucrune_local_io *io, int flags, int32_t guest_fds[2]);
int sucrune_local_eventfd2(struct sucrune_local_io *io, uint32_t initial, int flags);
int sucrune_local_epoll_create1(struct sucrune_local_io *io, int flags);
int sucrune_local_epoll_ctl(struct sucrune_local_io *io, int32_t epfd, int operation,
                            int32_t fd, const struct sucrune_local_event *event);

/* A non-NULL guest signal mask is explicitly unsupported, never installed as
 * the host mask. sigset_size is validated when a mask is supplied. Null masks
 * preserve the host's SIGSYS/async-signal policy. No automatic EINTR retry.
 * events has room for min(max_events,64) normalized entries; larger max_events
 * (including libuv's 1024) are accepted, with at most 64 events per call. */
int sucrune_local_epoll_pwait(struct sucrune_local_io *io, int32_t epfd,
    struct sucrune_local_event *events, int max_events, int timeout_ms,
    const uint64_t *signal_mask, size_t sigset_size);

/* poll count is bounded by the active descriptor limit. Negative FDs are ignored; missing FDs report
 * POLLNVAL and return immediately while other ready entries are also returned.
 * timeout is immutable input; optional remaining receives the raw Linux ppoll
 * remaining timeout on success/EINTR. Caller validates/copies guest memory and
 * holds any required memory ownership across the call. */
int sucrune_local_ppoll(struct sucrune_local_io *io, struct sucrune_local_pollfd *fds,
    size_t count, const struct sucrune_local_timespec *timeout,
    struct sucrune_local_timespec *remaining, const uint64_t *signal_mask, size_t sigset_size);
/* Three ARM64 guest descriptor sets, ordered read/write/exception. Real
 * pselect6 tests retained aliases. The optional private wake FD only causes
 * EINTR. No guest mask is ever installed in the native process. */
int sucrune_local_pselect(struct sucrune_local_io *io,const struct sucrune_local_fdset input[3],
    struct sucrune_local_fdset output[3],
    const struct sucrune_local_timespec *timeout,struct sucrune_local_timespec *remaining,int wake_fd);

#endif
