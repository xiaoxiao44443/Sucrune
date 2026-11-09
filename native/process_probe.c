#include "process_probe.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROBE_MAGIC 0x53555050U
#define EVENT_FD 3
#define LEASE_FD 4
#define CHILD_LEASE_FD 5
#define MAX_EVENTS 40U
#define PROBE_BUDGET_MS 6000
enum step { PS_WRAPPER_SUBREAPER=1, PS_WRAPPER_FORK, PS_WRAPPER_CHILD_SETUP,
    PS_INITIAL_EXEC, PS_RUNNER_IDENTITY, PS_RUNNER_SUBREAPER, PS_HELPER_THREAD,
    PS_BIONIC_FORK, PS_CHILD_PDEATH, PS_RAW_CLONE, PS_WORKER_NNP,
    PS_WORKER_FILTER, PS_WORKER_DENIED, PS_SUPERVISOR_UNFILTERED,
    PS_SUPERVISOR_EXEC, PS_REEXEC_IDENTITY, PS_REEXEC_UNFILTERED,
    PS_CHILD_WAIT, PS_CHILD_LEASE, PS_HELPER_JOIN,
    PS_GUARDIAN_FORK, PS_LEAF_FORK, PS_LEAF_PDEATH, PS_GUARDIAN_WAIT,
    PS_PDEATH_DELIVERY, PS_FINISHED, PS_UNSUPPORTED, PS_INTERNAL,
    PS_WRAPPER_MASK, PS_WRAPPER_WAIT, PS_WRAPPER_GROUP };
struct event { uint32_t magic, step; int64_t rc; int32_t error, pid, uid, detail; };
_Static_assert(sizeof(struct event)==32U,"bounded process probe event");
static const char *step_name(unsigned int step) {
    static const char *const names[]={"invalid", "wrapper_subreaper", "wrapper_fork", "wrapper_child_setup",
        "initial_exec", "runner_identity", "runner_subreaper", "bionic_helper_thread",
        "bionic_fork", "child_parent_death_setup", "raw_clone_worker", "worker_no_new_privs",
        "worker_seccomp_filter", "worker_getppid_denied", "supervisor_getppid_unfiltered",
        "supervisor_execve", "reexec_identity", "reexec_getppid_unfiltered",
        "child_waitpid", "child_lease_eof", "bionic_helper_join",
        "guardian_fork", "leaf_fork", "leaf_parent_death_setup", "guardian_waitpid",
        "parent_death_sigkill_waitpid", "finished", "unsupported_architecture", "internal_failure",
        "wrapper_signal_mask", "wrapper_waitpid", "wrapper_process_group"};
    return step<sizeof(names)/sizeof(names[0]) ? names[step] : "invalid";
}

/* These assembly leaves do not touch Bionic TLS, errno, allocator or locks.
 * Raw worker inherits a TLS pointer but never uses it; this fixture does not
 * implement production guest TLS/gates or authorize arbitrary post-fork C. */
static inline __attribute__((always_inline)) long raw6(long nr,long a,long b,long c,long d,long e,long f) {
#if defined(__aarch64__)
    register long x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
    register long x8 __asm__("x8")=nr;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory","cc");
    return x0;
#elif defined(__x86_64__)
    register long r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9) : "rcx","r11","memory","cc");
    return result;
#else
#error Unsupported build architecture
#endif
}
#define RAW0(n) raw6((n),0,0,0,0,0,0)
#define RAW1(n,a) raw6((n),(long)(a),0,0,0,0,0)
#define RAW2(n,a,b) raw6((n),(long)(a),(long)(b),0,0,0,0)
#define RAW3(n,a,b,c) raw6((n),(long)(a),(long)(b),(long)(c),0,0,0)
static __attribute__((no_stack_protector)) void emit_raw(enum step step,long rc,int detail) {
    struct event value={PROBE_MAGIC,(uint32_t)step,rc,rc<0 ? (int)-rc : 0,
        (int32_t)RAW0(SYS_getpid),(int32_t)RAW0(SYS_getuid),detail};
    (void)raw6(SYS_sendto,EVENT_FD,(long)&value,(long)sizeof(value),MSG_DONTWAIT|MSG_NOSIGNAL,0,0);
}
static void emit(enum step step,long rc,int detail) { emit_raw(step,rc,detail); }
static __attribute__((no_stack_protector)) _Noreturn void raw_exit(int status) {
    (void)RAW1(SYS_exit_group,status); __builtin_unreachable();
}
static __attribute__((no_stack_protector)) long raw_millis(void) {
    struct timespec now;
    long rc=RAW2(SYS_clock_gettime,CLOCK_MONOTONIC,&now);
    return rc<0 ? rc : now.tv_sec*1000L+now.tv_nsec/1000000L;
}
static __attribute__((no_stack_protector)) void raw_tick(void) {
    const struct timespec pause={0,1000000L};
    (void)RAW2(SYS_nanosleep,&pause,NULL);
}
static __attribute__((no_stack_protector)) long arm_parent(pid_t parent) {
    long result=raw6(SYS_prctl,PR_SET_PDEATHSIG,SIGKILL,0,0,0,0);
    if(result==0 && RAW0(SYS_getppid)!=(long)parent) result=-ESRCH;
    return result;
}
static int await_child(pid_t child,int *status,long deadline) {
    for(;;) {
        pid_t result=waitpid(child,status,WNOHANG);
        if(result==child) return 0;
        if(result<0 && errno!=EINTR) return -errno;
        if(raw_millis()>=deadline) return -ETIMEDOUT;
        raw_tick();
    }
}
static int await_eof(int descriptor,long deadline) {
    unsigned char byte;
    for(;;) {
        ssize_t count=read(descriptor,&byte,1U);
        if(count==0) return 0;
        if(count>0) return -EPROTO; /* lease transports no payload */
        if(errno!=EAGAIN && errno!=EINTR) return -errno;
        if(raw_millis()>=deadline) return -ETIMEDOUT;
        raw_tick();
    }
}
struct dirent_wire { uint64_t inode; int64_t offset; uint16_t size; unsigned char type; char name[]; };
static __attribute__((no_stack_protector)) int close_inherited(void) {
    long scan=raw6(SYS_openat,AT_FDCWD,(long)"/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC,0,0,0);
    if(scan<0) return (int)scan;
    union { uint64_t align; unsigned char bytes[4096]; } buffer;
    int result=0;
    for(int pass=0;pass<2 && result==0;pass++) {
        unsigned int entries=0U;
        for(;;) {
            long count=RAW3(SYS_getdents64,scan,buffer.bytes,sizeof(buffer.bytes));
            if(count<=0) {if(count<0) result=(int)count;break;}
            size_t offset=0U;
            while(offset<(size_t)count) {
                if((size_t)count-offset<offsetof(struct dirent_wire,name)+1U) {result=-EPROTO;break;}
                const struct dirent_wire *item=(const void *)(buffer.bytes+offset);
                size_t size=item->size;
                if(size<offsetof(struct dirent_wire,name)+1U || size>(size_t)count-offset || ++entries>16384U) {result=-EOVERFLOW;break;}
                size_t length=size - offsetof(struct dirent_wire,name), i=0U;
                int fd=0,numeric=1;
                while(i<length && item->name[i]!='\0') {
                    unsigned char ch=(unsigned char)item->name[i++];
                    if(ch<'0' || ch>'9' || fd>(INT_MAX-(int)(ch-'0'))/10) {numeric=0;break;}
                    fd=fd*10+(int)(ch-'0');
                }
                if(i==length) {result=-EPROTO;break;}
                if(numeric && i!=0U && fd!=scan && fd!=EVENT_FD && fd!=LEASE_FD) (void)RAW1(SYS_close,fd);
                offset+=size;
            }
            if(result!=0) break;
        }
        if(pass==0 && result==0) {long rc=RAW3(SYS_lseek,scan,0,SEEK_SET);if(rc<0) result=(int)rc;}
    }
    (void)RAW1(SYS_close,scan);
    return result;
}

#if defined(__aarch64__)
struct worker_state { atomic_int ready; long nnp, filter, denied; };
_Static_assert(ATOMIC_INT_LOCK_FREE==2,"raw worker needs lock-free atomics");
static __attribute__((no_stack_protector)) void worker_body(void *opaque) {
    struct worker_state *state=opaque;
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,(uint32_t)offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)SYS_getppid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog filter={4,code};
    state->nnp=raw6(SYS_prctl,PR_SET_NO_NEW_PRIVS,1,0,0,0,0);
    state->filter=state->nnp==0 ? raw6(SYS_prctl,PR_SET_SECCOMP,SECCOMP_MODE_FILTER,(long)&filter,0,0,0) : -ECANCELED;
    state->denied=RAW0(SYS_getppid);
    atomic_store_explicit(&state->ready,1,memory_order_release);
    /* Remain alive until exec eliminates this filtered thread. */
    for(;;) raw_tick();
}
__attribute__((naked,no_stack_protector)) static long raw_thread(long flags,void *stack,
        void (*entry)(void *),void *argument) {
    __asm__ volatile("sub x1, x1, #16\n"
        "stp x2, x3, [x1]\n"
        "mov x2, xzr\nmov x3, xzr\nmov x4, xzr\nmov x8, #220\nsvc #0\n"
        "cbnz x0, 1f\nldp x16, x0, [sp], #16\nblr x16\n"
        "mov x0, #0\nmov x8, #93\nsvc #0\nbrk #0\n1: ret\n");
}
static __attribute__((no_stack_protector)) _Noreturn void supervisor_child(const char *path,
        char *const *arguments,char *const *environment,pid_t parent,int lease,
        void *stack,struct worker_state *worker) {
    long result=arm_parent(parent);emit_raw(PS_CHILD_PDEATH,result,0);
    if(result<0) raw_exit(121);
    result=RAW3(SYS_dup3,lease,CHILD_LEASE_FD,0);
    if(result<0) {emit_raw(PS_INTERNAL,result,1);raw_exit(121);}
    if(lease!=CHILD_LEASE_FD) (void)RAW1(SYS_close,lease);
    result=raw_thread(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM,stack,worker_body,worker);
    emit_raw(PS_RAW_CLONE,result,0);
    if(result<0) raw_exit(121);
    long start=raw_millis();
    while(atomic_load_explicit(&worker->ready,memory_order_acquire)==0) {
        if(raw_millis()-start>1000L) {emit_raw(PS_INTERNAL,-ETIMEDOUT,2);raw_exit(121);}
        raw_tick();
    }
    emit_raw(PS_WORKER_NNP,worker->nnp,0);
    emit_raw(PS_WORKER_FILTER,worker->filter,0);
    /* Expected -EACCES is recorded honestly; verified is a separate predicate. */
    emit_raw(PS_WORKER_DENIED,worker->denied,0);
    emit_raw(PS_SUPERVISOR_UNFILTERED,RAW0(SYS_getppid),0);
    result=RAW3(SYS_execve,path,arguments,environment);
    emit_raw(PS_SUPERVISOR_EXEC,result,0);
    raw_exit(122);
}
static void *helper_body(void *opaque) {
    atomic_int *state=opaque;
    atomic_store_explicit(state,1,memory_order_release);
    while(atomic_load_explicit(state,memory_order_acquire)!=2) raw_tick();
    return NULL;
}
struct leaf_ready { int32_t pid,error; };
static __attribute__((no_stack_protector)) long raw_read_until(int fd,void *bytes,size_t size,long deadline) {
    for(;;) {
        long result=RAW3(SYS_read,fd,bytes,size);
        if(result!=-EAGAIN && result!=-EINTR) return result;
        if(raw_millis()>=deadline) return -ETIMEDOUT;
        raw_tick();
    }
}
static __attribute__((no_stack_protector)) _Noreturn void guardian_body(pid_t parent,int ready[2],int output) {
    long result=arm_parent(parent);
    if(result<0) {emit_raw(PS_INTERNAL,result,3);raw_exit(123);}
    pid_t guardian=(pid_t)RAW0(SYS_getpid);
    result=raw6(SYS_clone,SIGCHLD,0,0,0,0,0);
    if(result==0) {
        (void)RAW1(SYS_close,ready[0]);(void)RAW1(SYS_close,output);
        long arm=arm_parent(guardian);
        emit_raw(PS_LEAF_PDEATH,arm,0);
        struct leaf_ready message={(int32_t)RAW0(SYS_getpid),arm<0 ? (int32_t)-arm : 0};
        (void)RAW3(SYS_write,ready[1],&message,sizeof(message));
        (void)RAW1(SYS_close,ready[1]);
        if(arm<0) raw_exit(124);
        /* This deadline is a final fallback if the parent-death mechanism fails. */
        long end=raw_millis()+2000L;
        while(raw_millis()<end) raw_tick();
        raw_exit(124);
    }
    emit_raw(PS_LEAF_FORK,result,0);
    (void)RAW1(SYS_close,ready[1]);
    if(result<0) raw_exit(123);
    struct leaf_ready message={0,0};
    long got=raw_read_until(ready[0],&message,sizeof(message),raw_millis()+1000L);
    if(got==(long)sizeof(message)) (void)RAW3(SYS_write,output,&message,sizeof(message));
    else {emit_raw(PS_INTERNAL,got<0 ? got : -EPROTO,4);(void)RAW2(SYS_kill,result,SIGKILL);}
    /* No signal sent to leaf: its SIGKILL must result from our process death. */
    raw_exit(9);
}
static void measure_parent_death(void) {
    int ready[2]={-1,-1}, receipt[2]={-1,-1};
    if(pipe2(ready,O_CLOEXEC|O_NONBLOCK)!=0 || pipe2(receipt,O_CLOEXEC|O_NONBLOCK)!=0) {
        emit(PS_INTERNAL,-errno,5);goto done;
    }
    pid_t parent=getpid(), guardian=fork();
    if(guardian==0) {(void)RAW1(SYS_close,receipt[0]);guardian_body(parent,ready,receipt[1]);}
    emit(PS_GUARDIAN_FORK,guardian<0 ? -errno : guardian,0);
    if(guardian<0) goto done;
    (void)close(ready[0]);ready[0]=-1;(void)close(ready[1]);ready[1]=-1;
    (void)close(receipt[1]);receipt[1]=-1;
    struct leaf_ready leaf={0,0};
    long got=raw_read_until(receipt[0],&leaf,sizeof(leaf),raw_millis()+1200L);
    int status=0;
    int waited=await_child(guardian,&status,raw_millis()+1200L);
    emit(PS_GUARDIAN_WAIT,waited==0 ? guardian : waited,status);
    if(waited<0) {(void)kill(guardian,SIGKILL);(void)await_child(guardian,&status,raw_millis()+300L);}
    if(got==(long)sizeof(leaf) && leaf.pid>0) {
        waited=await_child((pid_t)leaf.pid,&status,raw_millis()+1200L);
        emit(PS_PDEATH_DELIVERY,waited==0 && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL && leaf.error==0 ? 0 :
            waited<0 ? waited : -EIO,status);
        if(waited<0) {(void)kill((pid_t)leaf.pid,SIGKILL);(void)await_child((pid_t)leaf.pid,&status,raw_millis()+300L);}
    } else emit(PS_PDEATH_DELIVERY,got<0 ? got : -EPROTO,0);
done:
    for(int i=0;i<2;i++) {if(ready[i]>=0) (void)close(ready[i]);if(receipt[i]>=0) (void)close(receipt[i]);}
}
static void measure_fork_exec(const char *path) {
    int lease[2]={-1,-1};
    const size_t stack_size=128U*1024U;
    void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(stack==MAP_FAILED) {emit(PS_INTERNAL,-errno,6);return;}
    if(pipe2(lease,O_CLOEXEC|O_NONBLOCK)!=0) {emit(PS_INTERNAL,-errno,7);(void)munmap(stack,stack_size);return;}
    /* High source prevents fd5 remap from overwriting the source or read end. */
    int source=fcntl(lease[1],F_DUPFD_CLOEXEC,16);
    if(source<0) {emit(PS_INTERNAL,-errno,8);goto done;}
    (void)close(lease[1]);lease[1]=source;
    atomic_int helper=ATOMIC_VAR_INIT(0);pthread_t thread;
    int error=pthread_create(&thread,NULL,helper_body,&helper);
    emit(PS_HELPER_THREAD,error==0 ? 0 : -error,0);
    if(error!=0) goto done;
    while(atomic_load_explicit(&helper,memory_order_acquire)==0) raw_tick();
    char parent_text[32];(void)snprintf(parent_text,sizeof(parent_text),"%ld",(long)getpid());
    char *arguments[]={(char *)path,"--process-probe-reexec",parent_text,NULL};
    char *environment[]={"LANG=C",NULL};
    struct worker_state worker={.ready=ATOMIC_VAR_INIT(0),.nnp=-ECANCELED,.filter=-ECANCELED,.denied=0};
    pid_t parent=getpid(), child=fork();
    if(child==0) {
        (void)RAW1(SYS_close,lease[0]);
        supervisor_child(path,arguments,environment,parent,lease[1],(unsigned char *)stack+stack_size,&worker);
    }
    emit(PS_BIONIC_FORK,child<0 ? -errno : child,0);
    (void)close(lease[1]);lease[1]=-1;
    if(child>0) {
        int status=0;int result=await_child(child,&status,raw_millis()+2000L);
        emit(PS_CHILD_WAIT,result==0 ? child : result,status);
        if(result<0) {(void)kill(child,SIGKILL);(void)await_child(child,&status,raw_millis()+300L);}
        emit(PS_CHILD_LEASE,await_eof(lease[0],raw_millis()+300L),0);
    }
    atomic_store_explicit(&helper,2,memory_order_release);
    error=pthread_join(thread,NULL);emit(PS_HELPER_JOIN,error==0 ? 0 : -error,0);
done:
    for(int i=0;i<2;i++) if(lease[i]>=0) (void)close(lease[i]);
    (void)munmap(stack,stack_size);
}
#endif

int sucrune_process_probe_main(int argc,char **argv) {
    if(argc!=3 || argv==NULL || argv[0]==NULL || argv[0][0]!='/' ||
       (strcmp(argv[1],"--process-probe")!=0 && strcmp(argv[1],"--process-probe-reexec")!=0)) return 126;
    char *end=NULL;errno=0;long parent=strtol(argv[2],&end,10);
    if(errno!=0 || end==argv[2] || *end!='\0' || parent<=0 || parent>INT_MAX) return 126;
    long armed=arm_parent((pid_t)parent);
    if(armed<0) {emit(PS_INTERNAL,armed,9);return 125;}
    if(strcmp(argv[1],"--process-probe-reexec")==0) {
        emit(PS_REEXEC_IDENTITY,0,(int)getppid());
        emit(PS_REEXEC_UNFILTERED,RAW0(SYS_getppid),0);
        /* Both leases remain open until kernel process teardown. */
        return 0;
    }
    emit(PS_RUNNER_IDENTITY,0,(int)getppid());
    if(getpgrp()!=getpid()) {emit(PS_INTERNAL,-EPROTO,10);return 125;}
#if defined(__aarch64__)
    int result=prctl(PR_SET_CHILD_SUBREAPER,1UL,0UL,0UL,0UL);
    emit(PS_RUNNER_SUBREAPER,result<0 ? -errno : 0,0);
    if(result==0) {measure_fork_exec(argv[0]);measure_parent_death();}
#else
    emit(PS_UNSUPPORTED,-ENOTSUP,0);
#endif
    emit(PS_FINISHED,0,0);
    return 0;
}

static void local_event(struct event *events,size_t *count,enum step step,long result,int detail) {
    if(*count<MAX_EVENTS) events[(*count)++]=(struct event){PROBE_MAGIC,(uint32_t)step,result,
        result<0 ? (int)-result : 0,(int32_t)getpid(),(int32_t)getuid(),detail};
}
static int has_result(const struct event *events,size_t count,enum step step,int positive,long exact) {
    for(size_t i=0U;i<count;i++) if(events[i].step==(uint32_t)step &&
        (positive ? events[i].rc>0 : events[i].rc==exact)) return 1;
    return 0;
}
static int has_wait(const struct event *events,size_t count,enum step step,int status) {
    for(size_t i=0U;i<count;i++) if(events[i].step==(uint32_t)step && events[i].rc>0 && events[i].detail==status) return 1;
    return 0;
}
int sucrune_process_probe_spawn(const char *path,char *report,size_t capacity) {
    if(path==NULL || path[0]!='/' || strnlen(path,PATH_MAX)==PATH_MAX || report==NULL || capacity<16384U) return -EINVAL;
    struct event events[MAX_EVENTS];size_t count=0U;
    int channels[2]={-1,-1},lease[2]={-1,-1},sources[2]={-1,-1};
    int status=0,waited=0,eof=0,all_reaped=0,old_reaper=0,reaper_set=0,error=0,timed_out=0,protocol_error=0,forced=0;
    pid_t child=-1;long began=raw_millis(),deadline=began+PROBE_BUDGET_MS;
    struct sigaction action;
    if(sigaction(SIGCHLD,NULL,&action)!=0) {error=errno;goto done;}
    if(action.sa_handler==SIG_IGN || (action.sa_flags&SA_NOCLDWAIT)!=0) {error=ENOTSUP;goto done;}
    int check_status=0;
    if(waitpid(-1,&check_status,WNOHANG)!=-1 || errno!=ECHILD) {error=EBUSY;goto done;}
    if(prctl(PR_GET_CHILD_SUBREAPER,&old_reaper,0UL,0UL,0UL)!=0) {error=errno;goto done;}
    int rc=prctl(PR_SET_CHILD_SUBREAPER,1UL,0UL,0UL,0UL);
    local_event(events,&count,PS_WRAPPER_SUBREAPER,rc==0 ? 0 : -errno,0);
    if(rc!=0) {error=errno;goto done;} reaper_set=1;
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,channels)!=0 ||
       pipe2(lease,O_CLOEXEC|O_NONBLOCK)!=0) {error=errno;goto done;}
    sources[0]=fcntl(channels[1],F_DUPFD_CLOEXEC,16);sources[1]=fcntl(lease[1],F_DUPFD_CLOEXEC,16);
    if(sources[0]<0 || sources[1]<0) {error=errno;goto done;}
    char parent_text[32];pid_t parent=getpid();(void)snprintf(parent_text,sizeof(parent_text),"%ld",(long)parent);
    char *arguments[]={(char *)path,"--process-probe",parent_text,NULL};char *environment[]={"LANG=C",NULL};
    sigset_t blocked,previous;sigfillset(&blocked);
    if(sigprocmask(SIG_SETMASK,&blocked,&previous)!=0) {error=errno;goto done;}
    child=fork();
    if(child==0) {
        long result=arm_parent(parent);
        if(result==0) result=RAW2(SYS_setpgid,0,0);
        if(result==0) result=RAW3(SYS_dup3,sources[0],EVENT_FD,0);
        if(result>=0) result=RAW3(SYS_dup3,sources[1],LEASE_FD,0);
        if(result>=0) result=close_inherited();
        emit_raw(PS_WRAPPER_CHILD_SETUP,result,0);
        if(result<0) raw_exit(125);
        result=RAW3(SYS_execve,path,arguments,environment);
        emit_raw(PS_INITIAL_EXEC,result,0);raw_exit(125);
    }
    int fork_error=errno;
    int mask_error=sigprocmask(SIG_SETMASK,&previous,NULL)==0 ? 0 : errno;
    local_event(events,&count,PS_WRAPPER_MASK,mask_error==0 ? 0 : -mask_error,0);
    local_event(events,&count,PS_WRAPPER_FORK,child<0 ? -fork_error : child,0);
    for(int i=0;i<2;i++) {(void)close(sources[i]);sources[i]=-1;}
    (void)close(channels[1]);channels[1]=-1;(void)close(lease[1]);lease[1]=-1;
    if(child<0) {error=fork_error;goto done;}
    /* Parent participates in group setup to close the timeout-before-exec race. */
    rc=setpgid(child,child);
    int group_error=rc==0 || errno==EACCES ? 0 : errno;
    local_event(events,&count,PS_WRAPPER_GROUP,group_error==0 ? 0 : -group_error,0);
    if(mask_error!=0 || group_error!=0) {error=mask_error!=0 ? mask_error : group_error;deadline=raw_millis();}
    for(;;) {
        struct event value;ssize_t got;
        do {
            got=recv(channels[0],&value,sizeof(value),MSG_DONTWAIT|MSG_TRUNC);
            if(got>0) {
                if(got!=(ssize_t)sizeof(value) || value.magic!=PROBE_MAGIC || value.step<1U || value.step>PS_WRAPPER_GROUP ||
                    value.uid!=(int32_t)getuid() || value.pid<=0 || count==MAX_EVENTS) protocol_error=1;
                else events[count++]=value;
            }
        } while(got>0);
        if(!waited) {
            siginfo_t information;memset(&information,0,sizeof(information));
            int result=waitid(P_PID,(id_t)child,&information,WEXITED|WNOHANG|WNOWAIT);
            if(result==0 && information.si_pid==child) {
                /* Keep leader zombie/PID reserved while killing any unexpected
                 * survivor. Never signal a group after reaping its leader. */
                (void)kill(-child,SIGKILL);
                if(await_child(child,&status,raw_millis()+500L)==0) waited=1;
                else {error=ECHILD;break;}
            } else if(result<0 && errno!=EINTR) {error=errno;break;}
        }
        if(waited) break;
        if(raw_millis()>=deadline || protocol_error) {
            timed_out=raw_millis()>=deadline;forced=1;
            /* PGID is the unreaped owned leader PID, never a user's process group. */
            (void)kill(-child,SIGKILL);(void)kill(child,SIGKILL);
            if(await_child(child,&status,raw_millis()+500L)==0) waited=1;
            break;
        }
        raw_tick();
    }
    if(!waited && child>0 && error!=ECHILD) {
        forced=1;
        (void)kill(-child,SIGKILL);(void)kill(child,SIGKILL);
        if(await_child(child,&status,raw_millis()+500L)==0) waited=1;
    }
    /* The dedicated Service owns no unrelated children. Any adopted survivor
     * is from this probe. The group is killed before reaping the leader on a
     * forced path; normal path does not signal a possibly reused PGID. */
    {
        long end=raw_millis()+700L;
        for(;;) {
            int adopted_status=0;pid_t adopted=waitpid(-1,&adopted_status,WNOHANG);
            if(adopted>0) continue;
            if(adopted<0 && errno==ECHILD) {all_reaped=1;break;}
            if(raw_millis()>=end) break;
            raw_tick();
        }
    }
    eof=await_eof(lease[0],raw_millis()+300L)==0;
    /* Drain packets already queued at leader exit. */
    for(;;) {
        struct event value;ssize_t got=recv(channels[0],&value,sizeof(value),MSG_DONTWAIT|MSG_TRUNC);
        if(got<=0) break;
        if(got!=(ssize_t)sizeof(value) || value.magic!=PROBE_MAGIC || value.step<1U || value.step>PS_WRAPPER_GROUP ||
            value.uid!=(int32_t)getuid() || value.pid<=0 || count==MAX_EVENTS) protocol_error=1;
        else events[count++]=value;
    }
done:
    if(error!=0) local_event(events,&count,PS_INTERNAL,-error,11);
    for(int i=0;i<2;i++) {if(channels[i]>=0) (void)close(channels[i]);if(lease[i]>=0) (void)close(lease[i]);if(sources[i]>=0) (void)close(sources[i]);}
    if(reaper_set && (child<0 || all_reaped)) (void)prctl(PR_SET_CHILD_SUBREAPER,(unsigned long)old_reaper,0UL,0UL,0UL);
    int cleanup=child<0 || (waited && eof && all_reaped);
    int verified=cleanup && waited && WIFEXITED(status) && WEXITSTATUS(status)==0 &&
        has_result(events,count,PS_FINISHED,0,0) && !protocol_error && !timed_out && error==0 &&
        has_result(events,count,PS_RAW_CLONE,1,0) && has_result(events,count,PS_WORKER_FILTER,0,0) &&
        has_result(events,count,PS_WORKER_DENIED,0,-EACCES) && has_result(events,count,PS_SUPERVISOR_UNFILTERED,1,0) &&
        has_result(events,count,PS_REEXEC_UNFILTERED,1,0) && has_result(events,count,PS_CHILD_LEASE,0,0) &&
        has_result(events,count,PS_PDEATH_DELIVERY,0,0) && has_result(events,count,PS_HELPER_JOIN,0,0) &&
        has_wait(events,count,PS_CHILD_WAIT,0) && has_wait(events,count,PS_GUARDIAN_WAIT,9<<8);
    int written=snprintf(report,capacity,"{\"schema_version\":1,\"kind\":\"process_capability\",\"wrapper_uid\":%ld,\"wrapper_pid\":%ld,"
        "\"runner_pid\":%ld,\"runner_waited\":%s,\"runner_exit_code\":%d,\"runner_signal\":%d,\"descendants_reaped\":%s,"
        "\"lease_eof\":%s,\"cleanup_verified\":%s,\"timed_out\":%s,\"forced_cleanup\":%s,\"protocol_error\":%s,"
        "\"error_number\":%d,\"mechanism_verified\":%s,\"deadline_ms\":%d,\"elapsed_ms\":%ld,\"operations\":[",
        (long)getuid(),(long)getpid(),(long)child,waited?"true":"false",waited&&WIFEXITED(status)?WEXITSTATUS(status):-1,
        waited&&WIFSIGNALED(status)?WTERMSIG(status):0,all_reaped?"true":"false",eof?"true":"false",cleanup?"true":"false",
        timed_out?"true":"false",forced?"true":"false",protocol_error?"true":"false",error,verified?"true":"false",PROBE_BUDGET_MS,raw_millis()-began);
    if(written<0 || (size_t)written>=capacity) return -ENOSPC;
    size_t used=(size_t)written;
    for(size_t i=0U;i<count;i++) {
        const struct event *value=&events[i];
        written=snprintf(report+used,capacity-used,"%s{\"name\":\"%s\",\"attempted\":true,\"success\":%s,\"rc\":%lld,"
            "\"errno\":%d,\"pid\":%d,\"uid\":%d,\"detail\":%d}",i==0U?"":",",step_name(value->step),value->rc>=0?"true":"false",
            (long long)value->rc,value->error,value->pid,value->uid,value->detail);
        if(written<0 || (size_t)written>=capacity-used) return -ENOSPC;used+=(size_t)written;
    }
    written=snprintf(report+used,capacity-used,"],\"not_tested\":[\"guest continuation and TLS\",\"Linux fork/exec/wait API\",\"PTY and controlling terminal\",\"cross-UID signalling\"]}");
    return written<0 || (size_t)written>=capacity-used ? -ENOSPC : 0;
}
