#ifndef SUCRUNE_GUEST_ABI_H
#define SUCRUNE_GUEST_ABI_H
#include <stdint.h>
#include <stddef.h>
/* Linux AArch64 UAPI stat layout, independent of the broker's host libc. */
struct sucrune_arm64_stat {
    uint64_t device, inode;
    uint32_t mode, nlink, uid, gid;
    uint64_t rdevice, pad1;
    int64_t size;
    int32_t block_size, pad2;
    int64_t blocks, atime_sec;
    uint64_t atime_nsec;
    int64_t mtime_sec;
    uint64_t mtime_nsec;
    int64_t ctime_sec;
    uint64_t ctime_nsec;
    uint32_t unused[2];
};
_Static_assert(sizeof(struct sucrune_arm64_stat) == 128U, "AArch64 stat ABI");
_Static_assert(offsetof(struct sucrune_arm64_stat, size) == 48U, "AArch64 stat size offset");
struct sucrune_project_owner {
    uint32_t broker_uid, broker_gid, guest_uid, guest_gid;
    const uint32_t *groups;
    size_t group_count;
};

/* Project files live under the Android manager's UID. Only map that owner on
 * regular files and directories, preserving foreign ownership and PTY identity. */
static inline void sucrune_project_stat_owner(struct sucrune_arm64_stat *st, const struct sucrune_project_owner *owner) {
    uint32_t type = st->mode & 0170000U;
    if (type != 0100000U && type != 0040000U) return;
    if (st->uid == owner->broker_uid) st->uid = owner->guest_uid;
    if (st->gid == owner->broker_gid) st->gid = owner->guest_gid;
}
/* The loader maps the broker's pinned regular inode itself. Select precisely
 * one guest mode class; this decision is independent of Android mount flags. */
static inline int sucrune_project_executable(struct sucrune_arm64_stat *st, const struct sucrune_project_owner *owner) {
    if ((st->mode & 0170000U) != 0100000U) return 0;
    sucrune_project_stat_owner(st, owner);
    if (st->uid == owner->guest_uid) return (st->mode & 0100U) != 0U;
    if (st->gid == owner->guest_gid) return (st->mode & 0010U) != 0U;
    for (size_t i = 0; i < owner->group_count; i++) {
        if (st->gid == owner->groups[i]) return (st->mode & 0010U) != 0U;
    }
    return (st->mode & 0001U) != 0U;
}
#endif
