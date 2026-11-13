#include "guest_landlock.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

struct anchor {
    atomic_uint refs;
    int fd;
    dev_t dev;
    ino_t ino;
};
struct rule { struct anchor *anchor; unsigned int allowed; };
/* Domain layers are immutable; a later add_rule affects the builder alone. */
struct ll_layer {
    atomic_uint refs;
    unsigned int handled;
    size_t count;
    struct rule rules[];
};
struct ll_ruleset {
    atomic_uint refs;
    pthread_mutex_t lock;
    struct ll_layer *current;
};
static void drop_layer(struct ll_layer *layer) {
    if (atomic_fetch_sub(&layer->refs, 1U) != 1U) return;
    for (size_t i = 0; i < layer->count; i++) {
        struct anchor *a = layer->rules[i].anchor;
        if (atomic_fetch_sub(&a->refs, 1U) == 1U) {
            if (a->fd >= 0) (void)close(a->fd);
            free(a);
        }
    }
    free(layer);
}
int ll_create(uint64_t handled, struct ll_ruleset **out) {
    if (!handled) return -ENOMSG;
    if (handled & ~(uint64_t)LL_ALL) return -EINVAL;
    struct ll_ruleset *set = calloc(1, sizeof(*set));
    if (!set) return -ENOMEM;
    set->current = calloc(1, sizeof(*set->current));
    if (!set->current) { free(set); return -ENOMEM; }
    int err = pthread_mutex_init(&set->lock, NULL);
    if (err) { free(set->current); free(set); return -err; }
    atomic_init(&set->refs, 1U);
    atomic_init(&set->current->refs, 1U);
    set->current->handled = (unsigned int)handled;
    *out = set;
    return 0;
}
void ll_hold(struct ll_ruleset *set) { (void)atomic_fetch_add(&set->refs, 1U); }
void ll_put(struct ll_ruleset *set) {
    if (set && atomic_fetch_sub(&set->refs, 1U) == 1U) {
        drop_layer(set->current);
        (void)pthread_mutex_destroy(&set->lock);
        free(set);
    }
}
static bool matches(const struct anchor *a, int fd, const struct stat *st) {
    return fd < 0 ? a->fd == fd : a->fd >= 0 && a->dev == st->st_dev && a->ino == st->st_ino;
}
int ll_add(struct ll_ruleset *set, uint64_t rights, int fd) {
    if (!rights) return -ENOMSG;
    struct stat st = {0};
    if (fd >= 0) {
        if (fstat(fd, &st) < 0) return -errno;
    } else if (fd != LL_DEV_NULL) return -EBADF;
    if (!S_ISDIR(st.st_mode) && (rights & ~(uint64_t)LL_FILE)) return -EINVAL;
    (void)pthread_mutex_lock(&set->lock);
    struct ll_layer *old = set->current;
    int err = -EINVAL;
    if (rights & ~(uint64_t)old->handled) goto done;
    size_t pos = 0;
    while (pos < old->count && !matches(old->rules[pos].anchor, fd, &st)) pos++;
    size_t count = old->count + (pos == old->count ? 1U : 0U);
    /* Pins and snapshots have a bounded footprint, independent of guest input. */
    if (count > 1024U) { err = -E2BIG; goto done; }
    struct ll_layer *next = calloc(1, sizeof(*next) + count * sizeof(struct rule));
    if (!next) { err = -ENOMEM; goto done; }
    atomic_init(&next->refs, 1U);
    next->handled = old->handled;
    for (size_t i = 0; i < old->count; i++) {
        next->rules[i] = old->rules[i];
        (void)atomic_fetch_add(&next->rules[i].anchor->refs, 1U);
    }
    next->count = old->count;
    if (pos == old->count) {
        struct anchor *a = calloc(1, sizeof(*a));
        if (!a) { err = -ENOMEM; drop_layer(next); goto done; }
        a->fd = fd < 0 ? fd : fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd >= 0 && a->fd < 0) { err = -errno; free(a); drop_layer(next); goto done; }
        atomic_init(&a->refs, 1U);
        a->dev = st.st_dev;
        a->ino = st.st_ino;
        next->rules[pos].anchor = a;
        next->count++;
    }
    next->rules[pos].allowed |= (unsigned int)rights;
    set->current = next;
    drop_layer(old);
    err = 0;
done:
    (void)pthread_mutex_unlock(&set->lock);
    return err;
}
int ll_restrict(struct ll_domain *d, struct ll_ruleset *set) {
    if (!d->no_new_privs) return -EPERM;
    if (d->count == LL_MAX_LAYERS) return -E2BIG;
    (void)pthread_mutex_lock(&set->lock);
    (void)atomic_fetch_add(&set->current->refs, 1U);
    d->layers[d->count++] = set->current;
    (void)pthread_mutex_unlock(&set->lock);
    return 0;
}
void ll_inherit(struct ll_domain *child, const struct ll_domain *parent) {
    *child = *parent;
    for (unsigned int i = 0; i < child->count; i++) (void)atomic_fetch_add(&child->layers[i]->refs, 1U);
}
void ll_release(struct ll_domain *d) {
    while (d->count) drop_layer(d->layers[--d->count]);
}
static unsigned int object_rights(const struct ll_layer *layer, int fd, const struct stat *st) {
    for (size_t j = 0; j < layer->count; j++) {
        if (matches(layer->rules[j].anchor, fd, st)) return layer->rules[j].allowed;
    }
    return 0;
}
static void add_rights(const struct ll_domain *d, int fd, const struct stat *st, unsigned int allowed[]) {
    for (unsigned int i = 0; i < d->count; i++)
        allowed[i] |= object_rights(d->layers[i], fd, st);
}
static int collect(const struct ll_domain *d, int root, int parent, int target, unsigned int allowed[]) {
    struct stat root_st, bind_st, st;
    if (fstat(root, &root_st) < 0) return -errno;
    if (d->bind_root_plus_one && fstat(d->bind_root_plus_one - 1, &bind_st) < 0) return -errno;
    for (unsigned int i = 0; i < d->count; i++)
        allowed[i] = LL_ALL & ~(d->layers[i]->handled | LL_REFER);
    if (target != LL_NO_TARGET) {
        if (target >= 0 && fstat(target, &st) < 0) return -errno;
        add_rights(d, target, target < 0 ? NULL : &st, allowed);
    }
    /* The broker serializes pathname edits across project sessions while
     * walking. Compare pinned directory identities, not stale path strings. */
    int dir = fcntl(parent, F_DUPFD_CLOEXEC, 3);
    if (dir < 0) return -errno;
    int err = 0;
    for (;;) {
        if (fstat(dir, &st) < 0) { err = -errno; break; }
        add_rights(d, dir, &st, allowed);
        if (st.st_dev == root_st.st_dev && st.st_ino == root_st.st_ino) break;
        bool mount_root = d->bind_root_plus_one && bind_st.st_dev == st.st_dev && bind_st.st_ino == st.st_ino;
        int up = mount_root ? fcntl(d->bind_parent_plus_one - 1, F_DUPFD_CLOEXEC, 3)
                            : openat(dir, "..", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (up < 0) { err = -errno; break; }
        struct stat higher;
        if (fstat(up, &higher) < 0) { err = -errno; close(up); break; }
        if (higher.st_dev == st.st_dev && higher.st_ino == st.st_ino) { close(up); err = -EACCES; break; }
        close(dir);
        dir = up;
    }
    close(dir);
    return err;
}
int ll_allowed(const struct ll_domain *d, int root, int parent, int target, unsigned int *rights) {
    *rights = LL_ALL;
    if (!d->count) return 0;
    unsigned int allowed[LL_MAX_LAYERS];
    int err = collect(d, root, parent, target, allowed);
    if (err) return err;
    for (unsigned int i = 0; i < d->count; i++) *rights &= allowed[i];
    return 0;
}
int ll_check(const struct ll_domain *d, int root, int parent, int target, unsigned int rights) {
    if (!d->count || !rights) return 0;
    unsigned int allowed;
    int err = ll_allowed(d, root, parent, target, &allowed);
    if (err) return err;
    return (rights & ~allowed) ? -EACCES : 0;
}
int ll_reparent(const struct ll_domain *d, int root, int old_parent, int child, int new_parent, mode_t mode) {
    if (!d->count) return 0;
    struct stat from, to;
    if (fstat(old_parent, &from) < 0 || fstat(new_parent, &to) < 0) return -errno;
    if (from.st_dev == to.st_dev && from.st_ino == to.st_ino) return 0;
    unsigned int source[LL_MAX_LAYERS], dest[LL_MAX_LAYERS];
    int err = collect(d, root, old_parent, LL_NO_TARGET, source);
    if (!err) err = collect(d, root, new_parent, LL_NO_TARGET, dest);
    if (err) return err;
    struct stat st;
    if (fstat(child, &st) < 0) return -errno;
    for (unsigned int i = 0; i < d->count; i++) {
        if (!(source[i] & dest[i] & LL_REFER)) return -EXDEV;
        unsigned int origin = source[i] | object_rights(d->layers[i], child, &st);
        if (dest[i] & ~origin & (S_ISDIR(mode) ? LL_ALL : LL_FILE)) return -EXDEV;
    }
    return 0;
}
unsigned int ll_make_right(mode_t mode) {
    if (S_ISREG(mode)) return LL_MAKE_REG;
    if (S_ISDIR(mode)) return LL_MAKE_DIR;
    if (S_ISLNK(mode)) return LL_MAKE_SYM;
    if (S_ISCHR(mode)) return LL_MAKE_CHAR;
    if (S_ISBLK(mode)) return LL_MAKE_BLOCK;
    if (S_ISFIFO(mode)) return LL_MAKE_FIFO;
    if (S_ISSOCK(mode)) return LL_MAKE_SOCK;
    return LL_ALL;
}
