#ifndef SUCRUNE_PROJECT_SCOPE_H
#define SUCRUNE_PROJECT_SCOPE_H
#include <stdint.h>
#include <stddef.h>
#define SUCRUNE_SCOPE_LIMIT 128
/* Private host FDs. Only the executing Android runner can use these channels.
 * The root retains the service end. Fork gets a new lease; exec retains it. */
struct sucrune_scope { int bus, lease; };
int sucrune_scope_start(void);
int sucrune_scope_join(int bus);
int sucrune_scope_watch(int lease);
void sucrune_scope_monitor(void *lease);
void sucrune_scope_name(const char *program);
void sucrune_scope_disposition(unsigned int signo,uint64_t handler,uint64_t mask);
unsigned int sucrune_scope_pending(void);
int sucrune_scope_pids(int bus,int32_t *pids,size_t capacity);
int sucrune_scope_proc(int bus,int32_t pid,int file);
int sucrune_scope_signal(int bus,int32_t pid,int signo);
#endif
