#ifndef SUCRUNE_GUEST_PROC_H
#define SUCRUNE_GUEST_PROC_H
#include "guest_abi.h"
#include "guest_processes.h"

struct sucrune_proc_file;
struct sucrune_proc_table { struct sucrune_proc_file *files[SUCRUNE_LINUX_FD_LIMIT]; };
/* state_lock serializes this bounded, per-execution table. Negative LOCAL
 * handles have no host FD alias. Existing fork preflight refuses to inherit
 * them; no real /proc directory descriptor reaches guest code. */
int sucrune_proc_path(const char *path);
int sucrune_proc_system_file(const char *path);
/* Also used in the raw fork child. Only the four named network tables
 * can request a snapshot; no host proc path crosses the broker boundary. */
int sucrune_proc_net_file(const char *path);
int sucrune_proc_net_open_flags(uint64_t flags);
enum { SUCRUNE_PROC_NET_DIR = 0x40, SUCRUNE_PROC_NET_RECLEN = 24 };
int sucrune_proc_is_net_dir(const char *path);
int sucrune_proc_net_dir_fd(struct sucrune_proc_table *table,int handle);
const void *sucrune_proc_net_dirents(size_t *length);
/* size includes NUL. Returns the new size, or negative errno. */
int sucrune_proc_net_at(char *path,size_t size,size_t capacity);
static inline void sucrune_proc_system_stat(int file,struct sucrune_arm64_stat *out) {
    if(file==SUCRUNE_PROC_NET_DIR) {
        *out=(struct sucrune_arm64_stat){.inode=0x1000,.mode=0040555,.nlink=2,.block_size=4096};
    } else {
        *out=(struct sucrune_arm64_stat){.inode=(uint64_t)(0x1000+file),.mode=0100444,.nlink=1,.block_size=4096};
    }
}
int sucrune_proc_self_stat(const char *path,int32_t self);
/* Pure formatter used by both the primary and the post-fork raw runner.
 * Output capacity must be at least length. The filtered record never grows. */
int sucrune_proc_filter_stat(const char *input,size_t length,unsigned char *output);
int sucrune_proc_path_stat(struct sucrune_process_group *group,const char *path,struct sucrune_arm64_stat *st);
int sucrune_proc_open(struct sucrune_proc_table *table,struct sucrune_process_group *group,int broker,
                      const char *path,uint64_t flags,int *handle);
int sucrune_proc_has(const struct sucrune_proc_table *table,int handle);
void sucrune_proc_close(struct sucrune_proc_table *table,int handle);
int sucrune_proc_stat(struct sucrune_proc_table *table,int handle,struct sucrune_arm64_stat *st);
int64_t sucrune_proc_read(struct sucrune_proc_table *table,int handle,void *out,size_t count,
                          int directory,int64_t position);
int64_t sucrune_proc_seek(struct sucrune_proc_table *table,int handle,int64_t offset,int whence);
#endif
