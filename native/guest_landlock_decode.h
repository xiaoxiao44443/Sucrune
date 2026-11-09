#ifndef SUCRUNE_GUEST_LANDLOCK_DECODE_H
#define SUCRUNE_GUEST_LANDLOCK_DECODE_H

#include "workspace_broker.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/stat.h>

/* Both ARM64 signal dispatchers use this decoder. The raw fork child has
 * guest TLS installed, so none of these helpers may call libc. */
enum {
    SUCRUNE_LL_PRCTL = 167,
    SUCRUNE_LL_CREATE = 444,
    SUCRUNE_LL_ADD = 445,
    SUCRUNE_LL_RESTRICT = 446,
    SUCRUNE_LL_NULL = -1000,
    SUCRUNE_LL_OTHER_SPECIAL = -1001
};
typedef int (*sucrune_ll_read)(void *, uintptr_t, void *, size_t);
typedef int (*sucrune_ll_handle)(void *, int32_t, int64_t *);

static inline int sucrune_ll_request(struct sucrune_request *r, const uint64_t *a,
    void *context, sucrune_ll_read read_guest, sucrune_ll_handle handle) {
    if (r->operation == SUCRUNE_LL_PRCTL) {
        if (a[0] != PR_SET_NO_NEW_PRIVS && a[0] != PR_GET_NO_NEW_PRIVS) return -ENOSYS;
        if (a[1] != (uint64_t)(a[0] == PR_SET_NO_NEW_PRIVS) || a[2] || a[3] || a[4]) return -EINVAL;
        r->args[0] = (int64_t)a[0];
        r->args[1] = (int64_t)a[1];
        return 0;
    }
    if (r->operation == SUCRUNE_LL_CREATE) {
        uint32_t flags = (uint32_t)a[2];
        r->args[2] = flags;
        if (flags != 0) return flags == 1U && a[0] == 0 && a[1] == 0 ? 0 : -EINVAL;
        if (!a[0]) return -EFAULT;
        if (a[1] < 8U) return -EINVAL;
        if (a[1] > 4096U) return -E2BIG;
        int error = read_guest(context, (uintptr_t)a[0], &r->args[0], 8U);
        if (error) return error;
        /* Linux accepts a larger struct only if all unknown fields are zero. */
        for (size_t i = 8; i < (size_t)a[1];) {
            unsigned char tail[64];
            size_t n = (size_t)a[1] - i;
            if (n > sizeof(tail)) n = sizeof(tail);
            if (a[0] > UINTPTR_MAX - i) return -EFAULT;
            error = read_guest(context, (uintptr_t)a[0] + i, tail, n);
            if (error) return error;
            for (size_t j = 0; j < n; j++) if (tail[j]) return -E2BIG;
            i += n;
        }
        r->args[1] = (int64_t)a[1];
        return 0;
    }
    if (r->operation == SUCRUNE_LL_RESTRICT) {
        if ((uint32_t)a[1] != 0) return -EINVAL;
        return handle(context, (int32_t)a[0], &r->args[0]);
    }
    if ((uint32_t)a[1] != 1U || (uint32_t)a[3] != 0) return -EINVAL;
    int error = handle(context, (int32_t)a[0], &r->args[0]);
    if (error) return error;
    /* struct landlock_path_beneath_attr is packed (12 bytes). */
    struct __attribute__((packed)) { uint64_t allowed; int32_t parent; } attr;
    error = read_guest(context, (uintptr_t)a[2], &attr, sizeof(attr));
    if (error) return error;
    r->args[1] = 1;
    r->args[2] = (int64_t)attr.allowed;
    return handle(context, attr.parent, &r->args[3]);
}

static inline int sucrune_ll_is_null(const struct stat *st) {
    return S_ISCHR(st->st_mode) && st->st_rdev == 0x103U; /* Linux /dev/null: major 1, minor 3 */
}

static inline uint64_t sucrune_ll_special_access(uint64_t flags, int directory) {
    if (flags & O_PATH) return 0;
    const uint64_t read_file = 1U << 2, read_dir = 1U << 3, write_file = 1U << 1;
    uint64_t access = (flags & O_ACCMODE) == O_WRONLY ? 0 : (directory ? read_dir : read_file);
    if ((flags & O_ACCMODE) != O_RDONLY) access |= write_file;
    return access;
}
#endif
