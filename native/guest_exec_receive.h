#ifndef SUCRUNE_EXEC_RECEIVE_H
#define SUCRUNE_EXEC_RECEIVE_H
#include "guest_exec.h"
#include "guest_network.h"
#include "pty_runtime.h"
int sucrune_exec_read_snapshot(int fd,void **bytes,size_t *size);
int sucrune_exec_check_packet(const struct sucrune_guest_exec *p,size_t bytes,int startup,
    const char **path,const char **argv,const char **envp);
int sucrune_exec_restore_fds(const struct sucrune_guest_exec *packet,struct sucrune_fd_table *table,
    struct sucrune_pty_table *ptys,struct sucrune_guest_network *network);
/* Present only in a fresh child runner. This process accepts one handoff. */
const struct sucrune_guest_exec *sucrune_linux_exec_state(void);
_Noreturn void sucrune_exec_child_exit(int code,int signal_number);
#endif
