#include "guest_threads.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#if defined(__aarch64__)
#include "guest_gates.h"
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define THREAD_ALT_SIZE (128U * 1024U)
#define REQUIRED_CLONE ((uint64_t)(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM))
/* Linux ignores obsolete CLONE_DETACHED for ordinary clone threads. musl
 * still includes it in pthread_create; it must not detach the host pthread. */
#define OPTIONAL_CLONE ((uint64_t)(CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|CLONE_DETACHED))
enum slot_state { SLOT_FREE, SLOT_RESERVED, SLOT_QUEUED, SLOT_STARTING, SLOT_LIVE, SLOT_JOINED };
struct sucrune_guest_thread {
    struct sucrune_thread_group *group;
    _Atomic int state, ready, launch, entry_ready, commit, complete, reply_ready, consumed;
    int startup_error;
    int64_t reply;
    pthread_t pthread;
    bool has_pthread, registered, launch_committed;
    volatile sig_atomic_t bootstrapping;
    uint64_t flags;
    uintptr_t parent_tid, tls, child_tid, clear_tid;
    struct sucrune_signal_cpu cpu;
    struct sucrune_signal_thread signals;
    _Alignas(16) struct sucrune_host_context host;
    struct sucrune_signal_gate gate;
    void *alternate;
    size_t alternate_size;
    stack_t previous_alternate;
    bool alternate_installed;
};
struct sucrune_thread_group {
    struct sucrune_thread_callbacks callbacks;
    void *user;
    pthread_t supervisor;
    struct sigaction previous_bootstrap;
    _Atomic int epoch, stopping, closing, cleanup_error;
    _Atomic unsigned int live, peak, created, joined;
    struct sucrune_guest_thread children[SUCRUNE_THREAD_CHILD_LIMIT];
};
static _Atomic(struct sucrune_thread_group *) active_group;
static _Thread_local struct sucrune_guest_thread *current_thread;
_Static_assert(sizeof(_Atomic int)==4U,"native futex word");
_Static_assert(ATOMIC_INT_LOCK_FREE==2,"signal-side thread submission atomics");

extern int sucrune_guest_thread_enter(struct sucrune_host_context *,
    struct sucrune_guest_thread *, uintptr_t, uint64_t, int64_t, int64_t);

static void futex_wake(_Atomic int *word) {
    (void)syscall(SYS_futex,(int *)(void *)word,FUTEX_WAKE_PRIVATE,INT32_MAX,NULL,NULL,0);
}
static void wait_word(_Atomic int *word,int expected) {
    while(atomic_load_explicit(word,memory_order_acquire)==expected) {
        long result=syscall(SYS_futex,(int *)(void *)word,FUTEX_WAIT_PRIVATE,expected,NULL,NULL,0);
        if(result<0 && errno!=EINTR && errno!=EAGAIN) _exit(159);
    }
}
static void notify_group(struct sucrune_thread_group *group) {
    (void)atomic_fetch_add_explicit(&group->epoch,1,memory_order_release);
    futex_wake(&group->epoch);
}
static void record_error(struct sucrune_thread_group *group,int error) {
    if(error==0) return;
    int empty=0;
    (void)atomic_compare_exchange_strong_explicit(&group->cleanup_error,&empty,error,
        memory_order_release,memory_order_relaxed);
}

/* Parse only the fixed host frame. Never follow EXTRA_CONTEXT guest pointers.
 * Inactive SVE headers have no payload; active SVE/SME requires a future ABI. */
static int fpsimd_record(void *native_context,unsigned char **record) {
    if(native_context==NULL || record==NULL) return -EINVAL;
    ucontext_t *context=native_context;
    unsigned char *bytes=context->uc_mcontext.__reserved;
    size_t limit=sizeof(context->uc_mcontext.__reserved),offset=0U;
    *record=NULL;
    while(offset+8U<=limit) {
        uint32_t header[2];memcpy(header,bytes+offset,sizeof(header));
        if(header[0]==0U && header[1]==0U) return *record==NULL ? -EINVAL : 0;
        if(header[1]<16U || (header[1]&15U)!=0U || header[1]>limit-offset) return -EINVAL;
        if(header[0]==SUCRUNE_SIGNAL_FPSIMD_MAGIC) {
            if(header[1]!=sizeof(struct sucrune_signal_fpsimd) || *record!=NULL) return -EINVAL;
            *record=bytes+offset;
        } else if(header[0]==UINT32_C(0x45535201)) {
            if(header[1]!=16U) return -EINVAL; /* ESR_CONTEXT */
        } else if(header[0]==UINT32_C(0x53564501)) {
            uint16_t flags;memcpy(&flags,bytes+offset+10U,sizeof(flags));
            if(header[1]!=16U || flags!=0U) return -ENOTSUP;
        } else return -ENOTSUP;
        offset+=header[1];
    }
    return -EINVAL;
}
int sucrune_thread_cpu_capture(const void *native_context,struct sucrune_signal_cpu *cpu) {
    if(cpu==NULL) return -EINVAL;
    unsigned char *record=NULL;
    int result=fpsimd_record((void *)native_context,&record);
    if(result!=0) return result;
    const ucontext_t *context=native_context;
    memcpy(cpu->regs,context->uc_mcontext.regs,sizeof(cpu->regs));
    cpu->sp=context->uc_mcontext.sp;cpu->pc=context->uc_mcontext.pc;
    cpu->pstate=context->uc_mcontext.pstate&SUCRUNE_SIGNAL_NZCV;
    memcpy(&cpu->fpsr,record+8U,sizeof(cpu->fpsr));
    memcpy(&cpu->fpcr,record+12U,sizeof(cpu->fpcr));
    memcpy(cpu->vectors,record+16U,sizeof(cpu->vectors));
    return 0;
}
int sucrune_thread_cpu_apply(void *native_context,const struct sucrune_signal_cpu *cpu) {
    if(cpu==NULL || (cpu->pstate&~SUCRUNE_SIGNAL_NZCV)!=0U) return -EINVAL;
    unsigned char *record=NULL;
    int result=fpsimd_record(native_context,&record);
    if(result!=0) return result;
    ucontext_t *context=native_context;
    memcpy(context->uc_mcontext.regs,cpu->regs,sizeof(cpu->regs));
    context->uc_mcontext.sp=cpu->sp;context->uc_mcontext.pc=cpu->pc;
    context->uc_mcontext.pstate=(context->uc_mcontext.pstate&~SUCRUNE_SIGNAL_NZCV)|cpu->pstate;
    memcpy(record+8U,&cpu->fpsr,sizeof(cpu->fpsr));
    memcpy(record+12U,&cpu->fpcr,sizeof(cpu->fpcr));
    memcpy(record+16U,cpu->vectors,sizeof(cpu->vectors));
    return 0;
}

static void thread_signal(int number,siginfo_t *info,void *native_context) {
    struct sucrune_guest_thread *thread=current_thread;
    if(thread==NULL) _exit(159);
    if(number==SIGUSR2) {
        if(thread->bootstrapping!=1 || info==NULL || info->si_code!=SI_TKILL ||
           info->si_pid!=getpid() || sucrune_thread_cpu_apply(native_context,&thread->cpu)!=0) _exit(159);
        thread->bootstrapping=0;
        return;
    }
    thread->group->callbacks.signal(thread->group->user,thread,number,info,native_context);
}
static void publish_ready(struct sucrune_guest_thread *thread,int error) {
    thread->startup_error=error;
    atomic_store_explicit(&thread->ready,1,memory_order_release);
    futex_wake(&thread->ready);
}

/* Called by entry assembly only after the full host context is saved, before
 * changing TPIDR_EL0. No guest code can reach an uninitialized registered gate. */
int sucrune_thread_before_enter(struct sucrune_guest_thread *thread) {
    struct sucrune_thread_group *group=thread->group;
    int result=sucrune_gate_register(&thread->gate);
    if(result>=0) {
        thread->registered=true;
        result=group->callbacks.prepare==NULL ? 0 : group->callbacks.prepare(group->user,thread);
    }
    publish_ready(thread,result);
    wait_word(&thread->launch,0);
    if(result!=0 || atomic_load_explicit(&thread->launch,memory_order_acquire)!=1) return -ECANCELED;
    if((thread->flags&(uint64_t)CLONE_CHILD_SETTID)!=0U)
        result=group->callbacks.write_tid(group->user,thread->child_tid,(int32_t)thread->gate.thread_id);
    thread->startup_error=result;
    atomic_store_explicit(&thread->entry_ready,1,memory_order_release);
    futex_wake(&thread->entry_ready);
    wait_word(&thread->commit,0);
    if(result!=0 || atomic_load_explicit(&thread->commit,memory_order_acquire)!=1) return -ECANCELED;
    thread->bootstrapping=1;
    return 0;
}
static void *thread_worker(void *value) {
    struct sucrune_guest_thread *thread=value;
    current_thread=thread;
    thread->gate.host=&thread->host;thread->gate.handler=thread_signal;
    thread->gate.thread_id=syscall(SYS_gettid);
    thread->signals.pid=getpid();thread->signals.tid=thread->gate.thread_id;thread->signals.uid=getuid();
    long page=sysconf(_SC_PAGESIZE);
    int error=0;
    if(page<=0 || (size_t)page>SIZE_MAX/2U-THREAD_ALT_SIZE) error=-EINVAL;
    else {
        thread->alternate_size=THREAD_ALT_SIZE+2U*(size_t)page;
        thread->alternate=mmap(NULL,thread->alternate_size,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(thread->alternate==MAP_FAILED) {thread->alternate=NULL;error=-errno;}
        else if(mprotect((unsigned char *)thread->alternate+(size_t)page,THREAD_ALT_SIZE,PROT_READ|PROT_WRITE)!=0) error=-errno;
        else {
            stack_t alternate={.ss_sp=(unsigned char *)thread->alternate+(size_t)page,.ss_size=THREAD_ALT_SIZE};
            if(sigaltstack(&alternate,&thread->previous_alternate)!=0) error=-errno;
            else thread->alternate_installed=true;
        }
    }
    sigset_t mask;sigfillset(&mask);sigdelset(&mask,SIGSYS);sigdelset(&mask,SIGUSR2);
    const int fatal[]={SIGSEGV,SIGBUS,SIGILL,SIGFPE,SIGABRT};
    for(size_t i=0;i<sizeof(fatal)/sizeof(fatal[0]);i++) sigdelset(&mask,fatal[i]);
    if(error==0) {int result=pthread_sigmask(SIG_SETMASK,&mask,NULL);if(result!=0) error=-result;}
    if(error!=0) publish_ready(thread,error);
    else (void)sucrune_guest_thread_enter(&thread->host,thread,thread->tls,thread->cpu.regs[18],
        (int64_t)getpid(),thread->gate.thread_id);
    /* No signal handler may reference this gate once retirement begins. */
    sigfillset(&mask);(void)pthread_sigmask(SIG_SETMASK,&mask,NULL);
    if(thread->registered) {
        int result=sucrune_gate_unregister(&thread->gate);
        if(result!=0) _exit(159);
        thread->registered=false;
    }
    if(thread->alternate_installed && sigaltstack(&thread->previous_alternate,NULL)!=0) _exit(159);
    if(thread->alternate!=NULL && munmap(thread->alternate,thread->alternate_size)!=0) _exit(159);
    thread->alternate=NULL;current_thread=NULL;
    atomic_store_explicit(&thread->complete,1,memory_order_release);
    notify_group(thread->group);
    return NULL;
}
static void start_slot(struct sucrune_guest_thread *thread) {
    struct sucrune_thread_group *group=thread->group;
    atomic_store_explicit(&thread->state,SLOT_STARTING,memory_order_release);
    int result=pthread_create(&thread->pthread,NULL,thread_worker,thread);
    if(result!=0) {
        thread->reply=-result;
        atomic_store_explicit(&thread->state,SLOT_JOINED,memory_order_release);
    } else {
        thread->has_pthread=true;
        (void)atomic_fetch_add_explicit(&group->created,1U,memory_order_relaxed);
        wait_word(&thread->ready,0);
        result=thread->startup_error;
        if(result==0 && (thread->flags&(uint64_t)CLONE_PARENT_SETTID)!=0U)
            result=group->callbacks.write_tid(group->user,thread->parent_tid,(int32_t)thread->gate.thread_id);
        atomic_store_explicit(&thread->launch,result==0 ? 1 : -1,memory_order_release);
        futex_wake(&thread->launch);
        if(result==0) {
            wait_word(&thread->entry_ready,0);
            result=thread->startup_error;
            thread->launch_committed=result==0;
            atomic_store_explicit(&thread->commit,result==0 ? 1 : -1,memory_order_release);
            futex_wake(&thread->commit);
        }
        thread->reply=result==0 ? thread->gate.thread_id : result;
        if(result!=0) {
            /* clone failure lets glibc immediately free its TCB/guest stack.
             * Finish the aborted host thread before publishing that failure,
             * and never clear a TID belonging to an uncommitted launch. */
            if(pthread_join(thread->pthread,NULL)!=0) _exit(159);
            thread->has_pthread=false;
            (void)atomic_fetch_add_explicit(&group->joined,1U,memory_order_relaxed);
            atomic_store_explicit(&thread->state,SLOT_JOINED,memory_order_release);
        } else atomic_store_explicit(&thread->state,SLOT_LIVE,memory_order_release);
    }
    atomic_store_explicit(&thread->reply_ready,1,memory_order_release);
    futex_wake(&thread->reply_ready);
}
static void *supervise(void *value) {
    struct sucrune_thread_group *group=value;
    for(;;) {
        int epoch=atomic_load_explicit(&group->epoch,memory_order_acquire);
        for(size_t i=0;i<SUCRUNE_THREAD_CHILD_LIMIT;i++) {
            struct sucrune_guest_thread *thread=&group->children[i];
            int state=atomic_load_explicit(&thread->state,memory_order_acquire);
            if(state==SLOT_QUEUED) {start_slot(thread);state=atomic_load_explicit(&thread->state,memory_order_acquire);}
            if(state==SLOT_LIVE && atomic_load_explicit(&thread->complete,memory_order_acquire)!=0) {
                if(!thread->has_pthread || pthread_join(thread->pthread,NULL)!=0) _exit(159);
                thread->has_pthread=false;
                (void)atomic_fetch_add_explicit(&group->joined,1U,memory_order_relaxed);
                if(thread->launch_committed && thread->clear_tid!=0U)
                    record_error(group,group->callbacks.clear_tid(group->user,thread->clear_tid));
                atomic_store_explicit(&thread->state,SLOT_JOINED,memory_order_release);state=SLOT_JOINED;
            }
            if(state==SLOT_JOINED && atomic_load_explicit(&thread->consumed,memory_order_acquire)!=0) {
                atomic_store_explicit(&thread->state,SLOT_FREE,memory_order_release);
                (void)atomic_fetch_sub_explicit(&group->live,1U,memory_order_release);
                notify_group(group);
            }
        }
        if(atomic_load_explicit(&group->stopping,memory_order_acquire)!=0) break;
        wait_word(&group->epoch,epoch);
    }
    return NULL;
}

int sucrune_threads_create(const struct sucrune_thread_callbacks *callbacks,void *user,struct sucrune_thread_group **out) {
    if(callbacks==NULL || callbacks->signal==NULL || callbacks->write_tid==NULL || callbacks->clear_tid==NULL || out==NULL) return -EINVAL;
    *out=NULL;
    struct sucrune_thread_group *group=calloc(1U,sizeof(*group));
    if(group==NULL) return -ENOMEM;
    group->callbacks=*callbacks;group->user=user;
    for(size_t i=0;i<SUCRUNE_THREAD_CHILD_LIMIT;i++) group->children[i].group=group;
    struct sucrune_thread_group *empty=NULL;
    if(!atomic_compare_exchange_strong_explicit(&active_group,&empty,group,memory_order_acq_rel,memory_order_relaxed)) {free(group);return -EBUSY;}
    struct sigaction handler={.sa_sigaction=sucrune_signal_entry,.sa_flags=SA_SIGINFO|SA_ONSTACK};
    sigfillset(&handler.sa_mask);
    int error=0;
    if(sigaction(SIGUSR2,&handler,&group->previous_bootstrap)!=0) error=-errno;
    else {
        int result=pthread_create(&group->supervisor,NULL,supervise,group);
        if(result!=0) {error=-result;(void)sigaction(SIGUSR2,&group->previous_bootstrap,NULL);}
    }
    if(error!=0) {atomic_store_explicit(&active_group,NULL,memory_order_release);free(group);return error;}
    *out=group;return 0;
}
int64_t sucrune_threads_clone(struct sucrune_thread_group *group,uint64_t flags,uintptr_t stack,
        uintptr_t parent_tid,uintptr_t tls,uintptr_t child_tid,uint64_t signal_mask,const struct sucrune_signal_cpu *cpu) {
    if(group==NULL || cpu==NULL || stack==0U || (stack&15U)!=0U ||
       cpu->pc==0U || (cpu->pc&3U)!=0U || (cpu->pstate&~SUCRUNE_SIGNAL_NZCV)!=0U) return -EINVAL;
    if((flags&REQUIRED_CLONE)!=REQUIRED_CLONE || (flags&~(REQUIRED_CLONE|OPTIONAL_CLONE))!=0U) return -ENOTSUP;
    if(((flags&(uint64_t)CLONE_PARENT_SETTID)!=0U && (parent_tid==0U || (parent_tid&3U)!=0U)) ||
       ((flags&((uint64_t)CLONE_CHILD_SETTID|(uint64_t)CLONE_CHILD_CLEARTID))!=0U && (child_tid==0U || (child_tid&3U)!=0U))) return -EINVAL;
    if(atomic_load_explicit(&group->closing,memory_order_acquire)!=0) return -ECANCELED;
    struct sucrune_guest_thread *thread=NULL;
    for(size_t i=0;i<SUCRUNE_THREAD_CHILD_LIMIT;i++) {
        int free_slot=SLOT_FREE;
        if(atomic_compare_exchange_strong_explicit(&group->children[i].state,&free_slot,SLOT_RESERVED,
                memory_order_acq_rel,memory_order_relaxed)) {thread=&group->children[i];break;}
    }
    if(thread==NULL) return -EAGAIN;
    /* Slot storage persists until group destruction; no allocation in SIGSYS. */
    thread->startup_error=0;thread->reply=0;thread->has_pthread=false;thread->registered=false;thread->launch_committed=false;
    thread->bootstrapping=0;thread->alternate=NULL;thread->alternate_installed=false;
    thread->flags=flags;thread->parent_tid=parent_tid;thread->tls=tls;thread->child_tid=child_tid;
    thread->clear_tid=(flags&(uint64_t)CLONE_CHILD_CLEARTID)!=0U ? child_tid : 0U;
    thread->cpu=*cpu;thread->cpu.regs[0]=0U;thread->cpu.sp=stack;
    memset(&thread->signals,0,sizeof(thread->signals));thread->signals.mask=signal_mask;
    memset(&thread->host,0,sizeof(thread->host));memset(&thread->gate,0,sizeof(thread->gate));
    atomic_store_explicit(&thread->ready,0,memory_order_relaxed);
    atomic_store_explicit(&thread->launch,0,memory_order_relaxed);
    atomic_store_explicit(&thread->entry_ready,0,memory_order_relaxed);
    atomic_store_explicit(&thread->commit,0,memory_order_relaxed);
    atomic_store_explicit(&thread->complete,0,memory_order_relaxed);
    atomic_store_explicit(&thread->reply_ready,0,memory_order_relaxed);
    atomic_store_explicit(&thread->consumed,0,memory_order_relaxed);
    unsigned int live=atomic_fetch_add_explicit(&group->live,1U,memory_order_relaxed)+1U;
    unsigned int peak=atomic_load_explicit(&group->peak,memory_order_relaxed);
    while(peak<live && !atomic_compare_exchange_weak_explicit(&group->peak,&peak,live,memory_order_relaxed,memory_order_relaxed)) { }
    atomic_store_explicit(&thread->state,SLOT_QUEUED,memory_order_release);notify_group(group);
    wait_word(&thread->reply_ready,0);
    int64_t result=thread->reply;
    atomic_store_explicit(&thread->consumed,1,memory_order_release);notify_group(group);
    return result;
}
int sucrune_threads_join(struct sucrune_thread_group *group) {
    if(group==NULL) return -EINVAL;
    while(atomic_load_explicit(&group->live,memory_order_acquire)!=0U) {
        int epoch=atomic_load_explicit(&group->epoch,memory_order_acquire);
        if(atomic_load_explicit(&group->live,memory_order_acquire)==0U) break;
        wait_word(&group->epoch,epoch);
    }
    return atomic_load_explicit(&group->cleanup_error,memory_order_acquire);
}
int sucrune_threads_destroy(struct sucrune_thread_group *group) {
    if(group==NULL) return -EINVAL;
    atomic_store_explicit(&group->closing,1,memory_order_release);
    int error=sucrune_threads_join(group);
    atomic_store_explicit(&group->stopping,1,memory_order_release);notify_group(group);
    if(pthread_join(group->supervisor,NULL)!=0) _exit(159);
    if(sigaction(SIGUSR2,&group->previous_bootstrap,NULL)!=0 && error==0) error=-errno;
    atomic_store_explicit(&active_group,NULL,memory_order_release);free(group);return error;
}
void sucrune_threads_stats(struct sucrune_thread_group *group,struct sucrune_thread_stats *stats) {
    if(group==NULL || stats==NULL) return;
    *stats=(struct sucrune_thread_stats){
        .live=atomic_load_explicit(&group->live,memory_order_acquire),
        .peak=atomic_load_explicit(&group->peak,memory_order_relaxed),
        .created=atomic_load_explicit(&group->created,memory_order_relaxed),
        .joined=atomic_load_explicit(&group->joined,memory_order_relaxed),
        .cleanup_error=atomic_load_explicit(&group->cleanup_error,memory_order_acquire)};
}
struct sucrune_guest_thread *sucrune_thread_current(void) {return current_thread;}
struct sucrune_signal_gate *sucrune_thread_gate(struct sucrune_guest_thread *thread) {return thread==NULL ? NULL : &thread->gate;}
int64_t sucrune_thread_tid(const struct sucrune_guest_thread *thread) {return thread==NULL ? -1 : thread->gate.thread_id;}
int sucrune_thread_on_altstack(const struct sucrune_guest_thread *thread,uintptr_t address) {
    if(thread==NULL || thread->alternate==NULL || thread->alternate_size<THREAD_ALT_SIZE) return 0;
    uintptr_t low=(uintptr_t)thread->alternate+(thread->alternate_size-THREAD_ALT_SIZE)/2U;
    return address>=low && address-low<THREAD_ALT_SIZE;
}
struct sucrune_signal_thread *sucrune_thread_signals(struct sucrune_guest_thread *thread) {return thread==NULL ? NULL : &thread->signals;}
uint64_t *sucrune_thread_signal_mask(struct sucrune_guest_thread *thread) {return thread==NULL ? NULL : &thread->signals.mask;}
void sucrune_thread_set_clear_tid(struct sucrune_guest_thread *thread,uintptr_t address) {if(thread!=NULL) thread->clear_tid=address;}
void sucrune_thread_exit(struct sucrune_guest_thread *thread,void *native_context) {
    if(thread==NULL || native_context==NULL || current_thread!=thread) _exit(159);
    ucontext_t *context=native_context;
    context->uc_mcontext.regs[0]=(uint64_t)(uintptr_t)&thread->host;
    context->uc_mcontext.sp=thread->host.sp;
    context->uc_mcontext.pc=(uint64_t)(uintptr_t)&sucrune_guest_return;
}
#else
int sucrune_thread_cpu_capture(const void *context,struct sucrune_signal_cpu *cpu) {(void)context;(void)cpu;return -ENOTSUP;}
int sucrune_thread_cpu_apply(void *context,const struct sucrune_signal_cpu *cpu) {(void)context;(void)cpu;return -ENOTSUP;}
int sucrune_threads_create(const struct sucrune_thread_callbacks *cb,void *u,struct sucrune_thread_group **g) {(void)cb;(void)u;if(g!=NULL)*g=NULL;return -ENOTSUP;}
int sucrune_threads_join(struct sucrune_thread_group *g) {(void)g;return -ENOTSUP;}
int sucrune_threads_destroy(struct sucrune_thread_group *g) {(void)g;return -ENOTSUP;}
void sucrune_threads_stats(struct sucrune_thread_group *g,struct sucrune_thread_stats *s) {(void)g;if(s!=NULL)memset(s,0,sizeof(*s));}
int64_t sucrune_threads_clone(struct sucrune_thread_group *g,uint64_t f,uintptr_t sp,uintptr_t p,uintptr_t tls,uintptr_t c,uint64_t m,const struct sucrune_signal_cpu *cpu) {(void)g;(void)f;(void)sp;(void)p;(void)tls;(void)c;(void)m;(void)cpu;return -ENOTSUP;}
struct sucrune_guest_thread *sucrune_thread_current(void) {return NULL;}
struct sucrune_signal_gate *sucrune_thread_gate(struct sucrune_guest_thread *t) {(void)t;return NULL;}
int64_t sucrune_thread_tid(const struct sucrune_guest_thread *t) {(void)t;return -1;}
int sucrune_thread_on_altstack(const struct sucrune_guest_thread *t,uintptr_t a) {(void)t;(void)a;return 0;}
struct sucrune_signal_thread *sucrune_thread_signals(struct sucrune_guest_thread *t) {(void)t;return NULL;}
uint64_t *sucrune_thread_signal_mask(struct sucrune_guest_thread *t) {(void)t;return NULL;}
void sucrune_thread_set_clear_tid(struct sucrune_guest_thread *t,uintptr_t a) {(void)t;(void)a;}
void sucrune_thread_exit(struct sucrune_guest_thread *t,void *c) {(void)t;(void)c;}
#endif
