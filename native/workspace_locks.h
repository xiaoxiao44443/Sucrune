#ifndef SUCRUNE_WORKSPACE_LOCKS_H
#define SUCRUNE_WORKSPACE_LOCKS_H
#include <stdint.h>

struct sucrune_inode_owner;
struct sucrune_record_locks { struct sucrune_inode_owner *head; };
/* AArch64 LP64 struct flock. The host never consumes guest padding. */
struct sucrune_record_lock {
    int16_t type, whence;
    int32_t padding;
    int64_t start, length;
    int32_t pid, tail_padding;
};
int sucrune_record_lock_op(struct sucrune_record_locks *, int file, int command, int pid,
                           struct sucrune_record_lock *);
void sucrune_record_close(struct sucrune_record_locks *, int file);
void sucrune_record_destroy(struct sucrune_record_locks *);
#endif
