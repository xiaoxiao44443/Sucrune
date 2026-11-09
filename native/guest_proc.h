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
int sucrune_proc_self_stat(const char *path,int32_t self);
/* Pure formatter used by both the primary and the post-fork raw runner.
 * Output capacity must be at least length. The filtered record never grows. */
int sucrune_proc_filter_stat(const char *input,size_t length,unsigned char *output);
int sucrune_proc_path_stat(struct sucrune_process_group *group,const char *path,struct sucrune_arm64_stat *st);
int sucrune_proc_open(struct sucrune_proc_table *table,struct sucrune_process_group *group,
                      const char *path,uint64_t flags,int *handle);
int sucrune_proc_has(const struct sucrune_proc_table *table,int handle);
void sucrune_proc_close(struct sucrune_proc_table *table,int handle);
int sucrune_proc_stat(struct sucrune_proc_table *table,int handle,struct sucrune_arm64_stat *st);
int64_t sucrune_proc_read(struct sucrune_proc_table *table,int handle,void *out,size_t count,
                          int directory,int64_t position);
int64_t sucrune_proc_seek(struct sucrune_proc_table *table,int handle,int64_t offset,int whence);
#endif
