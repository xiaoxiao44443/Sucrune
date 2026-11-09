#ifndef SUCRUNE_GUEST_FDS_H
#define SUCRUNE_GUEST_FDS_H
#include <stdint.h>
#include <stddef.h>

#define SUCRUNE_FD_LIMIT 64U
#define SUCRUNE_LINUX_FD_LIMIT 1024U
#define SUCRUNE_FD_CLOEXEC 1U

enum sucrune_fd_kind {
    SUCRUNE_FD_UNUSED = 0,
    SUCRUNE_FD_INPUT,
    SUCRUNE_FD_OUTPUT,
    SUCRUNE_FD_ERROR,
    SUCRUNE_FD_BROKER,
    SUCRUNE_FD_LOCAL
};

/* One description is shared by all dup aliases. Broker handles are opaque and
 * never interpreted as guest descriptor numbers. Local capture handles remain
 * owned by their caller; the release callback implements that ownership rule. */
struct sucrune_fd_resource {
    enum sucrune_fd_kind kind;
    int handle, status_flags;
    /* Optional runner-owned copy of a read-only broker OFD. May be installed
     * after enabling host alias hooks. Final drop closes it via alias_close. */
    int read_fd;
    unsigned int references;
};
struct sucrune_fd_entry { int resource; unsigned int flags; int host_alias; };
typedef int (*sucrune_fd_release)(void *, enum sucrune_fd_kind, int);
/* Optional real host dup per guest descriptor. create returns 0 and an owned
 * alias >=0, or -1 for a kind without a local alias (e.g. broker files).
 * A failing create consumes nothing. close consumes an alias even on error.
 * Canonical handle ownership remains with the resource release callback. */
typedef int (*sucrune_fd_alias_create)(void *, enum sucrune_fd_kind, int, int *);
typedef int (*sucrune_fd_alias_close)(void *, enum sucrune_fd_kind, int);
struct sucrune_fd_table {
    struct sucrune_fd_entry entries[SUCRUNE_LINUX_FD_LIMIT];
    struct sucrune_fd_resource resources[SUCRUNE_LINUX_FD_LIMIT];
    unsigned int limit, count, resource_count, peak;
    sucrune_fd_release release;
    /* Called once per logical guest close, even while another alias or a wait holds the OFD. */
    sucrune_fd_release descriptor_closed;
    void *context;
    sucrune_fd_alias_create alias_create;
    sucrune_fd_alias_close alias_close;
    void *alias_context;
};

void sucrune_fds_init(struct sucrune_fd_table *table, int input, int output, int error_output,
                     int read_flags, int write_flags, sucrune_fd_release release, void *context);
void sucrune_fds_init_empty(struct sucrune_fd_table *table,sucrune_fd_release release,void *context);
/* Select during startup, before publishing the table to other threads. */
void sucrune_fds_enable_linux(struct sucrune_fd_table *table);
/* Caller serializes table operations. Enable once; existing entry aliases are
 * all prepared before installation, and a failure rolls them all back. Old
 * callers without these hooks retain the original virtual-only behavior. */
int sucrune_fds_enable_aliases(struct sucrune_fd_table *table, sucrune_fd_alias_create create,
                              sucrune_fd_alias_close close, void *context);
/* Borrowed stable FD: valid only while caller prevents descriptor close/reuse.
 * Waiters must retain a dup under that lock and release the lock before sleep.
 * epoll_ctl targets must use this stable alias under the short table lock. */
int sucrune_fds_alias(const struct sucrune_fd_table *table, uint64_t descriptor);
struct sucrune_fd_resource *sucrune_fds_get(struct sucrune_fd_table *table, uint64_t descriptor);
/* Retain an open description without publishing another guest FD. Serialise
 * with all other table calls. A blocked operation can safely use its handle
 * after another thread closes and reuses the original descriptor number. */
int sucrune_fds_hold(struct sucrune_fd_table *table,uint64_t descriptor);
int sucrune_fds_drop(struct sucrune_fd_table *table,unsigned int resource);
/* Preflight has no side effects. Check it before broker open can create/truncate. */
int sucrune_fds_available(const struct sucrune_fd_table *table);
int sucrune_fds_add(struct sucrune_fd_table *table, enum sucrune_fd_kind kind,
                   int handle, int status_flags, unsigned int flags);
/* Atomic multi-resource admission (pipe2): preflight capacity/flags and prepare
 * all aliases before mutating the table. Success adopts all canonical handles;
 * failure adopts none, leaves output untouched and only closes created aliases. */
int sucrune_fds_add_batch(struct sucrune_fd_table *table, enum sucrune_fd_kind kind,
    const int *handles, const int *status_flags, const unsigned int *flags,
    size_t count, int32_t *descriptors);
int sucrune_fds_close(struct sucrune_fd_table *table, uint64_t descriptor);
int sucrune_fds_get_flags(const struct sucrune_fd_table *table, uint64_t descriptor);
int sucrune_fds_set_flags(struct sucrune_fd_table *table, uint64_t descriptor, uint64_t flags);
int sucrune_fds_duplicate(struct sucrune_fd_table *table, uint64_t source,
                         uint64_t minimum, unsigned int cloexec);
/* dup3 semantics: same descriptor is EINVAL; replacing a live target is atomic
 * to the single guest thread. Close errors of the old target are ignored. */
int sucrune_fds_replace(struct sucrune_fd_table *table, uint64_t source,
                       uint64_t destination, unsigned int cloexec);
int sucrune_fds_exec(struct sucrune_fd_table *table);
int sucrune_fds_destroy(struct sucrune_fd_table *table);
#endif
