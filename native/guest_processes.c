#include "guest_processes.h"
#include <errno.h>
#if defined(__aarch64__)
#include "guest_fork_child.h"
#include "broker_transport.h"
#include "pty_broker.h"
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct child_watch {
    struct sucrune_process_group *group;
    pthread_t thread;
    pid_t pid;
    int ready,channel;
};
struct sucrune_process_group {
    pthread_t supervisor;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int stopping, pending, finished;
    int64_t outcome;
    struct sucrune_vfork_lease lease;
    struct sucrune_fork_launch launch;
    pid_t children[SUCRUNE_PROCESS_LIMIT];
    struct child_watch watches[SUCRUNE_PROCESS_LIMIT];
    struct sucrune_scope scope;
    int wake_fd;
    atomic_int notice_pending;
    struct sucrune_signal_info notice;
    struct sucrune_process_stats stats;
};
static int registered_child(const struct sucrune_process_group *group,pid_t pid);

/* The per-child socket was created before this exact fork. It is never in
 * the guest FD table and automatically closes on exec. The only request
 * moves its sender, not an arbitrary PID, into a live sibling's group. */
static void serve_sibling_groups(struct child_watch *watch) {
    struct sucrune_process_group *group=watch->group;
    for(;;) {
        int32_t pgid;
        ssize_t n;
        do { n=recv(watch->channel,&pgid,sizeof(pgid),MSG_TRUNC); } while(n<0 && errno==EINTR);
        if(n!=(ssize_t)sizeof(pgid)) break;
        int32_t result=-EPERM;
        (void)pthread_mutex_lock(&group->mutex);
        pid_t sid=getsid(0);
        /* Android children of zygote may inherit SID 0 without a controlling
         * terminal. A negative return is the getsid failure indicator. */
        int own_child=sid>=0 && registered_child(group,watch->pid) && getsid(watch->pid)==sid;
        if(own_child && pgid>0 && getpgid(watch->pid)==pgid) {
            /* Bash also calls setpgid for this child from the parent. */
            result=0;
        } else if(own_child && pgid!=watch->pid && registered_child(group,pgid) &&
                  getsid(pgid)==sid && getpgid(pgid)==pgid) {
            siginfo_t end={0};
            int rc;
            do { rc=waitid(P_PID,(id_t)pgid,&end,WEXITED|WNOHANG|WNOWAIT); } while(rc<0 && errno==EINTR);
            if(rc==0 && end.si_pid==0) result=setpgid(watch->pid,pgid)==0 ? 0 : -errno;
        }
        (void)pthread_mutex_unlock(&group->mutex);
        do { n=send(watch->channel,&result,sizeof(result),MSG_NOSIGNAL); } while(n<0 && errno==EINTR);
        if(n!=(ssize_t)sizeof(result)) break;
    }
    (void)close(watch->channel);
}
int sucrune_processes_wake_fd(const struct sucrune_process_group *group) {
    return group==NULL ? -1 : group->wake_fd;
}
int sucrune_processes_take_child_signal(struct sucrune_process_group *group,struct sucrune_signal_info *info) {
    if(group==NULL || info==NULL || !atomic_load_explicit(&group->notice_pending,memory_order_acquire)) return 0;
    int available=0;
    (void)pthread_mutex_lock(&group->mutex);
    if(atomic_load_explicit(&group->notice_pending,memory_order_relaxed)) {
        uint64_t value;
        if(read(group->wake_fd,&value,sizeof(value))!=(ssize_t)sizeof(value)) _exit(125);
        *info=group->notice;atomic_store_explicit(&group->notice_pending,0,memory_order_release);
        available=1;
    }
    (void)pthread_mutex_unlock(&group->mutex);
    return available;
}
static void *observe_child(void *opaque) {
    struct child_watch *watch=opaque;
    struct sucrune_process_group *group=watch->group;
    (void)pthread_mutex_lock(&group->mutex);
    while(watch->pid==0) (void)pthread_cond_wait(&group->changed,&group->mutex);
    pid_t pid=watch->pid;
    (void)pthread_mutex_unlock(&group->mutex);
    if(pid<0) return NULL;
    serve_sibling_groups(watch);
    siginfo_t actual={0};
    int result;
    do {result=waitid(P_PID,(id_t)pid,&actual,WEXITED|WNOWAIT);} while(result<0 && errno==EINTR);
    if(result!=0 || actual.si_pid!=pid) _exit(125);
    (void)pthread_mutex_lock(&group->mutex);
    if(!atomic_load_explicit(&group->notice_pending,memory_order_relaxed)) {
        struct sucrune_signal_info info={.signo=SIGCHLD,.code=actual.si_code,.pid=pid,.uid=actual.si_uid};
        /* Linux AArch64 SIGCHLD status follows si_uid at byte 24. */
        int32_t status=actual.si_status;
        memcpy((unsigned char *)&info+24U,&status,sizeof(status));
        group->notice=info;
        uint64_t one=1;
        if(write(group->wake_fd,&one,sizeof(one))!=(ssize_t)sizeof(one)) _exit(125);
        atomic_store_explicit(&group->notice_pending,1,memory_order_release);
    }
    watch->ready=1;
    (void)pthread_cond_broadcast(&group->changed);
    (void)pthread_mutex_unlock(&group->mutex);
    return NULL;
}
static int64_t now_ms(void) {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now)!=0) return -1;
    return (int64_t)now.tv_sec*1000+now.tv_nsec/1000000L;
}
static int await_launch(int channel) {
    int64_t deadline=now_ms()+2000;
    for(;;) {
        int64_t remaining=deadline-now_ms();
        if(remaining<=0) return -ETIMEDOUT;
        struct pollfd watch={.fd=channel,.events=POLLIN};
        int ready=poll(&watch,1,(int)remaining);
        if(ready<0 && errno==EINTR) continue;
        if(ready<=0) return ready==0 ? -ETIMEDOUT : -errno;
        int message=0;
        ssize_t bytes=recv(channel,&message,sizeof(message),MSG_DONTWAIT|MSG_TRUNC);
        if(bytes<0 && (errno==EAGAIN || errno==EINTR)) continue;
        if(bytes!=(ssize_t)sizeof(message)) return bytes<0 ? -errno : -EPROTO;
        return message<=0 && message>=-4095 ? message : -EPROTO;
    }
}
static int kill_and_wait(pid_t child,int *was_killed) {
    if(kill(child,SIGKILL)!=0 && errno!=ESRCH) return -errno;
    int status=0;pid_t result;
    do {result=waitpid(child,&status,0);} while(result<0 && errno==EINTR);
    if(result==child && was_killed!=NULL) *was_killed=WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL;
    return result==child ? 0 : -errno;
}
static int64_t launch_child(struct sucrune_fork_launch *launch,int *control_channel,struct sucrune_vfork_lease *lease) {
    int channels[2];
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channels)!=0) return -errno;
    pid_t parent=getpid();
    pid_t child=-1;
    int failed=0;
    if((launch->snapshot.flags&CLONE_VFORK)!=0) {
        int completion[2];
        if(pipe2(completion,O_CLOEXEC)!=0) failed=-errno;
        else {
            long result=sucrune_vfork_child_start(launch,channels[1],parent,completion[1],&lease->arena);
            (void)close(completion[1]);
            if(result<0) {failed=(int)result;(void)close(completion[0]);}
            else {child=(pid_t)result;lease->read_fd=completion[0];}
        }
    } else {
        child=fork();
        if(child==0) sucrune_fork_child_start(launch,channels[1],parent);
        if(child<0) failed=-errno;
    }
    (void)close(channels[1]);
    if(failed==0) failed=await_launch(channels[0]);
    if(failed==0) *control_channel=channels[0];
    else (void)close(channels[0]);
    if(failed!=0 && child>0) {
        int cleanup=kill_and_wait(child,NULL);
        if(cleanup!=0) _exit(125); /* cannot lose an owned PID */
        sucrune_processes_finish_vfork(lease);
    }
    return failed==0 ? child : failed;
}
static void *supervise(void *opaque) {
    struct sucrune_process_group *group=opaque;
    sigset_t blocked;
    sigfillset(&blocked);
    if(pthread_sigmask(SIG_SETMASK,&blocked,NULL)!=0) _exit(125);
    (void)pthread_mutex_lock(&group->mutex);
    for(;;) {
        while(!group->pending && !group->stopping) (void)pthread_cond_wait(&group->changed,&group->mutex);
        if(group->stopping) break;
        group->pending=0;
        unsigned int slot=0U;
        while(slot<SUCRUNE_PROCESS_LIMIT && group->children[slot]!=0) slot++;
        if(slot==SUCRUNE_PROCESS_LIMIT) _exit(125);
        struct child_watch *watch=&group->watches[slot];
        *watch=(struct child_watch){.group=group,.channel=-1};
        int observer_error=pthread_create(&watch->thread,NULL,observe_child,watch);
        int64_t outcome=-observer_error;
        if(observer_error==0) {
            (void)pthread_mutex_unlock(&group->mutex);
            outcome=launch_child(&group->launch,&watch->channel,&group->lease);
            (void)pthread_mutex_lock(&group->mutex);
            watch->pid=outcome>0 ? (pid_t)outcome : -1;
            (void)pthread_cond_broadcast(&group->changed);
            if(outcome<0) {
                (void)pthread_mutex_unlock(&group->mutex);
                if(pthread_join(watch->thread,NULL)!=0) _exit(125);
                (void)pthread_mutex_lock(&group->mutex);
            }
        }
        if(outcome>0) {
            group->children[slot]=(pid_t)outcome;
            group->stats.created++;group->stats.live++;
            if(group->stats.live>group->stats.peak) group->stats.peak=group->stats.live;
        }
        group->outcome=outcome;group->finished=1;
        (void)pthread_cond_broadcast(&group->changed);
    }
    (void)pthread_mutex_unlock(&group->mutex);
    return NULL;
}
int sucrune_processes_create(struct sucrune_process_group **out, struct sucrune_scope scope) {
    if(out==NULL) return -EINVAL;
    *out=NULL;
    struct sucrune_process_group *group=calloc(1U,sizeof(*group));
    if(group==NULL) return -ENOMEM;
    group->scope=scope;
    atomic_init(&group->notice_pending,0);
    int error=pthread_mutex_init(&group->mutex,NULL);
    if(error!=0) {free(group);return -error;}
    pthread_condattr_t attr;
    error=pthread_condattr_init(&attr);
    if(error==0) {
        error=pthread_condattr_setclock(&attr,CLOCK_MONOTONIC);
        if(error==0) error=pthread_cond_init(&group->changed,&attr);
        (void)pthread_condattr_destroy(&attr);
    }
    if(error!=0) {(void)pthread_mutex_destroy(&group->mutex);free(group);return -error;}
    group->wake_fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    error=group->wake_fd<0 ? errno : pthread_create(&group->supervisor,NULL,supervise,group);
    if(error!=0) {if(group->wake_fd>=0) (void)close(group->wake_fd);(void)pthread_cond_destroy(&group->changed);(void)pthread_mutex_destroy(&group->mutex);free(group);return -error;}
    *out=group;
    return 0;
}
/* Optional, bounded metadata only. Never expose a kernel FD, address or
 * workspace path to the guest's diagnostic stream. */
static void trace_fork_refusal(const struct sucrune_process_snapshot *snapshot,const char *reason,
        int guest_fd,int kind,int state) {
    if (!snapshot->trace_faults) return;
    char text[128];
    int n=snprintf(text,sizeof(text),"[sucrune-fork] unsupported %s guest_fd=%d kind=%d state=%d\n",reason,guest_fd,kind,state);
    if(n>0 && (size_t)n<sizeof(text)) (void)write(STDERR_FILENO,text,(size_t)n);
}
static void trace_broker_network(const struct sucrune_process_snapshot *snapshot) {
    if (!snapshot->trace_faults) return;
    const struct sucrune_fd_table *table=snapshot->descriptors;
    unsigned int printed=0;
    for(unsigned int i=0;i<table->limit && printed<8U;i++) {
        int id=table->entries[i].resource;
        if(id<0 || (unsigned int)id>=table->limit) continue;
        const struct sucrune_fd_resource *r=&table->resources[id];
        if(r->kind!=SUCRUNE_FD_LOCAL || !sucrune_guest_network_token(snapshot->network,r->handle)) continue;
        int type=sucrune_guest_network_type(snapshot->network,r->handle);
        if(type==SOCK_DGRAM) {
            trace_fork_refusal(snapshot,"broker-udp",(int)i,type,sucrune_guest_network_udp_state(snapshot->network,r->handle));
        } else {
            struct sockaddr_storage address;socklen_t n=sizeof(address),len=sizeof(int);
            int listener=0;
            (void)getsockopt(r->handle,SOL_SOCKET,SO_ACCEPTCONN,&listener,&len);
            int connected=getpeername(r->handle,(struct sockaddr *)&address,&n)==0;
            trace_fork_refusal(snapshot,"broker-tcp",(int)i,type,listener ? 2 : connected);
        }
        printed++;
    }
}
int64_t sucrune_processes_fork(struct sucrune_process_group *group,const struct sucrune_process_snapshot *snapshot,struct sucrune_vfork_lease *lease) {
    if(group==NULL || snapshot==NULL || lease==NULL || snapshot->descriptors==NULL || snapshot->space==NULL || snapshot->fixed_space==NULL || snapshot->broker<0 || snapshot->signal_actions==NULL) return -EINVAL;
    uint64_t allowed=UINT64_C(255)|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID;
    if((snapshot->flags & (CLONE_VM|CLONE_VFORK))==(CLONE_VM|CLONE_VFORK)) allowed|=CLONE_VM|CLONE_VFORK;
    if((snapshot->flags & UINT64_C(255))!=SIGCHLD || (snapshot->flags & ~allowed)!=0) {
        trace_fork_refusal(snapshot,"clone-flags",-1,0,0);return -ENOTSUP;
    }
    if((snapshot->cpu.sp & 15U)!=0U || (snapshot->cpu.pc & 3U)!=0U || snapshot->cpu.sp<16U) return -EINVAL;
    if((snapshot->flags & (CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID))!=0U &&
       ((snapshot->child_tid & 3U)!=0U || !(sucrune_space_access(snapshot->space,snapshot->child_tid,4U,1) ||
           sucrune_space_access(snapshot->fixed_space,snapshot->child_tid,4U,1)))) return -EFAULT;
    (void)pthread_mutex_lock(&group->mutex);
    int64_t result=-EAGAIN;
    if(group->stats.live==SUCRUNE_PROCESS_LIMIT || group->stopping) goto done;
    group->launch.snapshot=*snapshot;
    group->launch.snapshot.scope_bus=group->scope.bus;
    group->launch.parent_group=getpgid(0);
    group->launch.parent_session=getsid(0);
    if(group->launch.parent_group<0 || group->launch.parent_session<0) {result=-ESRCH;goto done;}
    const struct sucrune_fd_table *table=snapshot->descriptors;
    group->launch.fd_limit=table->limit;
    for(unsigned int i=0;i<table->limit;i++) {
        int resource=table->entries[i].resource;
        group->launch.aliases[i]=-1;group->launch.handles[i]=-1;group->launch.fd_flags[i]=0;
        struct sucrune_exec_fd *meta=&group->launch.metadata[i];
        *meta=(struct sucrune_exec_fd){.resource=-1,.local_alias=-1,.broker_handle=-1,.pty_number=-1};
        if(resource<0) continue;
        if((unsigned int)resource>=table->limit) {result=-EIO;goto done;}
        group->launch.fd_flags[i]=table->entries[i].flags;
        meta->resource=resource;meta->kind=(int32_t)table->resources[resource].kind;
        meta->status_flags=table->resources[resource].status_flags;
        group->launch.udp_resource[resource]=0;
        if(table->resources[resource].kind==SUCRUNE_FD_LOCAL) {
            meta->network_token=sucrune_guest_network_token(snapshot->network,table->resources[resource].handle);
            if (meta->network_token != 0) {
                int handle=table->resources[resource].handle;
                if (sucrune_guest_network_type(snapshot->network,handle)==SOCK_DGRAM) {
                    if (!snapshot->build_profile ||
                        sucrune_guest_network_udp_state(snapshot->network,handle)!=SUCRUNE_UDP_BOUND) {
                        trace_fork_refusal(snapshot,"udp-profile-or-state",(int)i,SOCK_DGRAM,sucrune_guest_network_udp_state(snapshot->network,handle));
                        result=-EOPNOTSUPP;goto done;
                    }
                    group->launch.udp_resource[resource]=1;
                } else if ((meta->status_flags&O_NONBLOCK)==0) {
                    trace_fork_refusal(snapshot,"blocking-socket",(int)i,sucrune_guest_network_type(snapshot->network,handle),0);
                    result=-EOPNOTSUPP;goto done;
                }
            }
        }
        if(table->resources[resource].kind==SUCRUNE_FD_BROKER) {
            int handle=table->resources[resource].handle;
            group->launch.handles[i]=handle;
            if(sucrune_pty_slave_handle(handle)) {
                int number=-1;
                for(unsigned int j=0;j<i;j++) if(group->launch.handles[j]==handle) {
                    number=group->launch.metadata[j].pty_number;break;
                }
                if(number<0) {
                    struct sucrune_request describe={.magic=SUCRUNE_BROKER_MAGIC,
                        .operation=SUCRUNE_PTY_DESCRIBE,.args={handle}};
                    struct sucrune_response reply;
                    result=sucrune_broker_exchange(snapshot->broker,&describe,&reply,NULL,2000);
                    if(result!=0) goto done;
                    if(reply.result<0) {result=reply.result;goto done;}
                    if(reply.size!=0U || reply.result>INT32_MAX) {result=-EPROTO;goto done;}
                    number=(int)reply.result;
                }
                meta->pty_kind=SUCRUNE_PTY_SLAVE;meta->pty_number=number;
            }
            continue;
        }
        if(table->resources[resource].kind==SUCRUNE_FD_LOCAL && snapshot->ptys!=NULL) for(unsigned int p=0;p<SUCRUNE_PTY_ENDPOINTS;p++) {
            const struct sucrune_pty_endpoint *endpoint=&snapshot->ptys->entries[p];
            if(endpoint->kind!=SUCRUNE_PTY_NONE && endpoint->fd==table->resources[resource].handle) {
                meta->pty_kind=(int32_t)endpoint->kind;meta->pty_number=endpoint->number;break;
            }
        }
        int alias=sucrune_fds_alias(table,i);
        if(alias<0) {
            trace_fork_refusal(snapshot,"missing-alias",(int)i,meta->kind,meta->status_flags);
            result=-EOPNOTSUPP;goto done;
        }
        group->launch.aliases[i]=alias;
    }
    struct sucrune_request request={.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_FORK_SESSION};
    struct sucrune_response response;
    int child_broker=-1;
    result=sucrune_broker_exchange(snapshot->broker,&request,&response,&child_broker,2000);
    if(result==0) result=response.result;
    if(result==-EOPNOTSUPP) {
        trace_fork_refusal(snapshot,"broker-session",-1,0,0);
        trace_broker_network(snapshot);
    }
    if(result!=0 || child_broker<0) {if(child_broker>=0) (void)close(child_broker);if(result==0) result=-EPROTO;goto done;}
    group->launch.broker=child_broker;
    group->lease=(struct sucrune_vfork_lease){.read_fd=-1};
    group->pending=1;group->finished=0;
    (void)pthread_cond_broadcast(&group->changed);
    while(!group->finished) (void)pthread_cond_wait(&group->changed,&group->mutex);
    result=group->outcome;
    if(result==-EOPNOTSUPP) trace_fork_refusal(snapshot,"child-launch",-1,0,0);
    if(result>0) *lease=group->lease;
    (void)close(child_broker);
done:
    (void)pthread_mutex_unlock(&group->mutex);
    return result;
}
void sucrune_processes_finish_vfork(struct sucrune_vfork_lease *lease) {
    if(lease->read_fd<0) return;
    char byte;
    ssize_t n;
    do {n=read(lease->read_fd,&byte,1);} while(n<0 && errno==EINTR);
    if(n!=0) _exit(125); /* we must never release the arena while a child uses it */
    (void)close(lease->read_fd);
    sucrune_vfork_release_arena(lease->arena);
    *lease=(struct sucrune_vfork_lease){.read_fd=-1};
}
/* Consume only an explicitly requested kernel job-control event. WEXITED is
 * absent here: the watcher must observe terminal SIGCHLD before we reap. */
static int job_status(pid_t child,int flags,int *status,struct rusage *usage) {
    siginfo_t event={0};
    long rc;
    do {rc=syscall(SYS_waitid,P_PID,(id_t)child,&event,flags|WNOHANG,usage);} while(rc<0 && errno==EINTR);
    if(rc<0) return errno==ECHILD?0:-errno;
    if(event.si_pid==0) return 0;
    if(event.si_pid!=child) return -EIO;
    if(event.si_code==CLD_STOPPED && (flags&WSTOPPED)!=0) *status=((event.si_status&255)<<8)|0x7f;
    else if(event.si_code==CLD_CONTINUED && (flags&WCONTINUED)!=0) *status=0xffff;
    else return -EIO;
    return child;
}
int64_t sucrune_processes_wait(struct sucrune_process_group *group,int64_t pid,unsigned int options,int *status,struct rusage *usage) {
    if(group==NULL || status==NULL) return -EINVAL;
    if(pid!=-1 && (pid<=0 || pid>INT32_MAX)) return -ENOTSUP;
    if((options & ~(unsigned int)(WNOHANG|WUNTRACED|WCONTINUED))!=0U) return -EINVAL;
    int job_flags=0;
    if((options&WUNTRACED)!=0U) job_flags|=WSTOPPED;
    if((options&WCONTINUED)!=0U) job_flags|=WCONTINUED;
    (void)pthread_mutex_lock(&group->mutex);
    for(;;) {
        int64_t result=-ECHILD;
        for(unsigned int i=0U;i<SUCRUNE_PROCESS_LIMIT;i++) {
            pid_t child=group->children[i];
            if(child==0 || (pid!=-1 && pid!=child)) continue;
            if(job_flags!=0 && !group->watches[i].ready) {
                int job=job_status(child,job_flags,status,usage);
                if(job!=0) {result=job;break;}
            }
            if(!group->watches[i].ready) {result=0;continue;}
            pid_t found=wait4(child,status,WNOHANG,usage);
            if(found==child) {
                if(pthread_join(group->watches[i].thread,NULL)!=0) _exit(125);
                group->children[i]=0;group->stats.live--;group->stats.waited++;result=found;break;
            }
            if(found<0 && errno!=EINTR) {result=-errno;break;}
            result=0;
        }
        if(result!=0 || (options&WNOHANG)!=0U) {
            (void)pthread_mutex_unlock(&group->mutex);
            return result;
        }
        if(job_flags==0) (void)pthread_cond_wait(&group->changed,&group->mutex);
        else {
            // Terminal changes wake the normal observer. Stops and continues
            // stay in the kernel until a guest requests their wait status.
            struct timespec until;
            int rc=clock_gettime(CLOCK_MONOTONIC,&until);
            if(rc!=0) {int saved=errno;(void)pthread_mutex_unlock(&group->mutex);return -saved;}
            until.tv_nsec+=20000000L;
            if(until.tv_nsec>=1000000000L) {until.tv_sec++;until.tv_nsec-=1000000000L;}
            rc=pthread_cond_timedwait(&group->changed,&group->mutex,&until);
            if(rc!=0 && rc!=ETIMEDOUT) {(void)pthread_mutex_unlock(&group->mutex);return -rc;}
        }
    }
}
int sucrune_processes_proc_pids(struct sucrune_process_group *group,int32_t *pids,size_t capacity) {
    if(pids==NULL || capacity<SUCRUNE_PROCESS_LIMIT+1U) return -EINVAL;
    if(group && group->scope.bus>=0) {
        int root=group->scope.lease<0;
        if(root) pids[0]=(int32_t)getpid();
        int n=sucrune_scope_pids(group->scope.bus,pids+root,capacity-(size_t)root);
        return n<0 ? n : n+root;
    }
    int count=1; pids[0]=(int32_t)getpid();
    if(group!=NULL) {
        (void)pthread_mutex_lock(&group->mutex);
        for(unsigned int i=0;i<SUCRUNE_PROCESS_LIMIT;i++)
            if(group->children[i]>0) pids[count++]=(int32_t)group->children[i];
        (void)pthread_mutex_unlock(&group->mutex);
    }
    return count;
}
int sucrune_processes_signal_child(struct sucrune_process_group *group,int32_t pid,int32_t signo) {
    if(pid<=0 && !(group && group->scope.bus>=0 && pid < -1 && pid != INT32_MIN)) return -EOPNOTSUPP;
    if(signo<0 || signo>64) return -EINVAL;
    if(group==NULL) return -ESRCH;
    if(group->scope.bus>=0) return sucrune_scope_signal(group->scope.bus,pid,signo);
    int result=-ESRCH;
    (void)pthread_mutex_lock(&group->mutex);
    for(unsigned int i=0;i<SUCRUNE_PROCESS_LIMIT;i++) {
        if(group->children[i]!=pid) continue;
        // The watcher only observes via WNOWAIT; actual waitpid and removal
        // take this mutex. This PID cannot be recycled before kill returns.
        if(signo!=0 && signo!=SIGKILL && signo!=SIGCONT) result=-EOPNOTSUPP;
        else result=kill((pid_t)pid,signo)==0?0:-errno;
        break;
    }
    (void)pthread_mutex_unlock(&group->mutex);
    return result;
}
int sucrune_processes_open_proc(struct sucrune_process_group *group,int32_t pid,int stat_file) {
    if(pid<=0 || stat_file<0 || stat_file>2) return -ENOENT;
    if(group && group->scope.bus>=0 && pid!=(int32_t)getpid()) {
        int fd=sucrune_scope_proc(group->scope.bus,pid,stat_file);
        return fd==-ESRCH ? -ENOENT : fd;
    }
    if(group!=NULL) (void)pthread_mutex_lock(&group->mutex);
    int authorized=pid==(int32_t)getpid(), result=-ENOENT;
    if(!authorized && group!=NULL) for(unsigned int i=0;i<SUCRUNE_PROCESS_LIMIT;i++)
        if(group->children[i]==pid) {authorized=1;break;}
    if(authorized) {
        char path[64];
        int n=snprintf(path,sizeof(path),"/proc/%d%s",(int)pid,stat_file?"/stat":"");
        if(n>0 && (size_t)n<sizeof(path)) {
            int flags=stat_file==0?(O_PATH|O_DIRECTORY):stat_file==1?O_RDONLY:O_PATH;
            int fd=open(path,O_CLOEXEC|O_NOFOLLOW|flags);
            result=fd<0?-errno:fd;
        }
    }
    if(group!=NULL) (void)pthread_mutex_unlock(&group->mutex);
    return result;
}
int64_t sucrune_processes_query_group(struct sucrune_process_group *group,int64_t pid,int session) {
    if (pid == 0 || pid == getpid()) {
        pid_t result = session ? getsid(0) : getpgid(0);
        return result < 0 ? -errno : result;
    }
    if (group == NULL || pid <= 0 || pid > INT32_MAX) return -ESRCH;
    int64_t result = -ESRCH;
    (void)pthread_mutex_lock(&group->mutex);
    for (unsigned int i=0; i<SUCRUNE_PROCESS_LIMIT; i++) if (group->children[i] == pid) {
        pid_t value = session ? getsid((pid_t)pid) : getpgid((pid_t)pid);
        result = value < 0 ? -errno : value;
        break;
    }
    (void)pthread_mutex_unlock(&group->mutex);
    return result;
}
static int registered_child(const struct sucrune_process_group *group,pid_t pid) {
    if(group==NULL || pid<=0) return 0;
    for(unsigned int i=0;i<SUCRUNE_PROCESS_LIMIT;i++)
        if(group->children[i]==pid) return 1;
    return 0;
}
static int authorized_group_locked(const struct sucrune_process_group *group,pid_t pgid) {
    if(pgid<=0) return 0;
    if(getpgid(0)==pgid) return 1;
    /* A still-unreaped, registered group leader pins the numeric PGID. The
     * final kernel operation checks the session again if a child raced setsid. */
    if(!registered_child(group,pgid)) return 0;
    pid_t sid=getsid(0);
    return sid>=0 && getsid(pgid)==sid && getpgid(pgid)==pgid;
}
int sucrune_processes_set_group(struct sucrune_process_group *group,int32_t pid,int32_t pgid) {
    if(pgid<0) return -EINVAL;
    if(pid<0) return -ESRCH;
    pid_t self=getpid(),target=pid==0 ? self : pid;
    pid_t destination=pgid==0 ? target : pgid;
    if(group!=NULL) (void)pthread_mutex_lock(&group->mutex);
    int rc;
    if(target!=self && !registered_child(group,target)) rc=-ESRCH;
    else if(destination!=target && !authorized_group_locked(group,destination)) rc=-EPERM;
    else rc=setpgid(target,destination)<0 ? -errno : 0;
    if(group!=NULL) (void)pthread_mutex_unlock(&group->mutex);
    return rc;
}
int sucrune_processes_set_foreground(struct sucrune_process_group *group,int tty,int32_t pgid) {
    if(pgid<=0) return -EINVAL;
    if(group!=NULL) (void)pthread_mutex_lock(&group->mutex);
    int rc=-EPERM;
    if(authorized_group_locked(group,pgid))
        rc=ioctl(tty,TIOCSPGRP,&pgid)<0 ? -errno : 0;
    if(group!=NULL) (void)pthread_mutex_unlock(&group->mutex);
    return rc;
}
int sucrune_processes_destroy(struct sucrune_process_group *group,struct sucrune_process_stats *stats) {
    if(group==NULL) return 0;
    int error=0;
    (void)pthread_mutex_lock(&group->mutex);
    for(unsigned int i=0U;i<SUCRUNE_PROCESS_LIMIT;i++) if(group->children[i]!=0) {
        pid_t child=group->children[i];
        if(!group->watches[i].ready && kill(child,SIGKILL)!=0 && errno!=ESRCH) _exit(125);
        while(!group->watches[i].ready) (void)pthread_cond_wait(&group->changed,&group->mutex);
        int status=0;pid_t got;
        do {got=waitpid(child,&status,0);} while(got<0 && errno==EINTR);
        if(got!=child || pthread_join(group->watches[i].thread,NULL)!=0) _exit(125);
        group->children[i]=0;group->stats.live--;group->stats.cleanup_reaped++;
        if(WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL) group->stats.killed++;
    }
    group->stopping=1;(void)pthread_cond_broadcast(&group->changed);
    (void)pthread_mutex_unlock(&group->mutex);
    int joined=pthread_join(group->supervisor,NULL);
    if(joined!=0) return -joined;
    if(stats!=NULL) *stats=group->stats;
    (void)close(group->wake_fd);
    (void)pthread_cond_destroy(&group->changed);(void)pthread_mutex_destroy(&group->mutex);free(group);
    return error;
}
#else
int sucrune_processes_set_group(struct sucrune_process_group *g,int32_t p,int32_t pg) {(void)g;(void)p;(void)pg;return -ENOTSUP;}
int sucrune_processes_set_foreground(struct sucrune_process_group *g,int fd,int32_t pg) {(void)g;(void)fd;(void)pg;return -ENOTSUP;}
int sucrune_processes_wake_fd(const struct sucrune_process_group *g) {(void)g;return -1;}
int sucrune_processes_take_child_signal(struct sucrune_process_group *g,struct sucrune_signal_info *i) {(void)g;(void)i;return 0;}
int64_t sucrune_processes_query_group(struct sucrune_process_group *g,int64_t p,int s) {(void)g;(void)p;(void)s;return -ENOTSUP;}
int sucrune_processes_proc_pids(struct sucrune_process_group *g,int32_t *p,size_t c) {(void)g;(void)p;(void)c;return -ENOTSUP;}
int sucrune_processes_open_proc(struct sucrune_process_group *g,int32_t p,int s) {(void)g;(void)p;(void)s;return -ENOTSUP;}
int sucrune_processes_signal_child(struct sucrune_process_group *g,int32_t p,int32_t s) {(void)g;(void)p;(void)s;return -ENOTSUP;}
int sucrune_processes_create(struct sucrune_process_group **out, struct sucrune_scope scope) {(void)scope;if(out) *out=NULL;return -ENOTSUP;}
int64_t sucrune_processes_fork(struct sucrune_process_group *g,const struct sucrune_process_snapshot *s,struct sucrune_vfork_lease *l) {(void)g;(void)s;(void)l;return -ENOTSUP;}
void sucrune_processes_finish_vfork(struct sucrune_vfork_lease *l) {(void)l;}
int64_t sucrune_processes_wait(struct sucrune_process_group *g,int64_t p,unsigned int o,int *s,struct rusage *u) {(void)g;(void)p;(void)o;(void)s;(void)u;return -ENOTSUP;}
int sucrune_processes_destroy(struct sucrune_process_group *g,struct sucrune_process_stats *s) {(void)g;(void)s;return 0;}
#endif
