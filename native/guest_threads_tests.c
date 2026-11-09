#include "guest_threads.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__aarch64__)
#include "guest_gates.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define CHECK(condition) do {if(!(condition)) {fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#condition);exit(1);}} while(0)
#define TEST_COUNT 64U
#define TEST_FLAGS ((uint64_t)(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|CLONE_DETACHED))
extern void sucrune_thread_test_guest(void);
extern void sucrune_thread_test_guest_end(void);
__asm__(
".text\n.p2align 4\n.global sucrune_thread_test_guest\n.hidden sucrune_thread_test_guest\nsucrune_thread_test_guest:\n"
"stp x0,x1,[sp,#0]\nstp x2,x3,[sp,#16]\nstp x4,x5,[sp,#32]\nstp x6,x7,[sp,#48]\n"
"stp x8,x9,[sp,#64]\nstp x10,x11,[sp,#80]\nstp x12,x13,[sp,#96]\nstp x14,x15,[sp,#112]\n"
"stp x16,x17,[sp,#128]\nstp x18,x19,[sp,#144]\nstp x20,x21,[sp,#160]\nstp x22,x23,[sp,#176]\n"
"stp x24,x25,[sp,#192]\nstp x26,x27,[sp,#208]\nstp x28,x29,[sp,#224]\nstr x30,[sp,#240]\n"
"mrs x0,tpidr_el0\nstr x0,[sp,#256]\n"
"stp q0,q1,[sp,#272]\nstp q2,q3,[sp,#304]\nstp q4,q5,[sp,#336]\nstp q6,q7,[sp,#368]\n"
"stp q8,q9,[sp,#400]\nstp q10,q11,[sp,#432]\nstp q12,q13,[sp,#464]\nstp q14,q15,[sp,#496]\n"
"stp q16,q17,[sp,#528]\nstp q18,q19,[sp,#560]\nstp q20,q21,[sp,#592]\nstp q22,q23,[sp,#624]\n"
"stp q24,q25,[sp,#656]\nstp q26,q27,[sp,#688]\nstp q28,q29,[sp,#720]\nstp q30,q31,[sp,#752]\n"
"mrs x0,fpcr\nstr x0,[sp,#784]\nmrs x0,fpsr\nstr x0,[sp,#792]\nmrs x0,nzcv\nstr x0,[sp,#800]\n"
"mov x8,#178\nsvc #0\nstr x0,[sp,#808]\nmov x8,#98\nsvc #0\nmov x0,#0\nmov x8,#93\nsvc #0\nb .\n"
".global sucrune_thread_test_guest_end\n.hidden sucrune_thread_test_guest_end\nsucrune_thread_test_guest_end:\n");

struct test_case {
    struct sucrune_signal_cpu cpu;
    _Atomic int32_t parent_tid,child_tid;
    _Alignas(16) unsigned char fake_tls[64];
    void *stack;
    size_t stack_size;
};
struct test_state {
    struct sucrune_thread_group *group;
    struct test_case cases[TEST_COUNT];
    _Atomic int fail_prepare,fail_parent_write,barrier,clear_count,signal_count,prepare_count;
};
static struct test_state tests;
static int prepare(void *opaque,struct sucrune_guest_thread *thread) {
    struct test_state *state=opaque;
    struct sucrune_signal_gate *gate=sucrune_thread_gate(thread);
    CHECK(gate!=NULL && gate->host!=NULL && gate->host->tpidr_el0!=0U);
    CHECK(sucrune_thread_current()==thread && sucrune_gate_find(gate->thread_id)==gate);
    CHECK(sucrune_thread_signals(thread)->tid==gate->thread_id);
    CHECK(sucrune_thread_signals(thread)->pid==getpid());
    sigset_t mask;CHECK(pthread_sigmask(SIG_SETMASK,NULL,&mask)==0);
    CHECK(sigismember(&mask,SIGUSR2)==0 && sigismember(&mask,SIGSYS)==0);
    (void)atomic_fetch_add(&state->prepare_count,1);
    if(atomic_exchange(&state->fail_prepare,0)!=0) return -ECANCELED;
    uintptr_t low=(uintptr_t)&sucrune_thread_test_guest,high=(uintptr_t)&sucrune_thread_test_guest_end;
    CHECK((low>>32U)==(high>>32U));
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,(unsigned int)offsetof(struct seccomp_data,instruction_pointer)+4U),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(low>>32U),0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,(unsigned int)offsetof(struct seccomp_data,instruction_pointer)),
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,(uint32_t)low,0,2),
        BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K,(uint32_t)high,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRAP|0x7452U),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    struct sock_fprog filter={.len=(unsigned short)(sizeof(code)/sizeof(code[0])),.filter=code};
    if(prctl(PR_SET_NO_NEW_PRIVS,1UL,0UL,0UL,0UL)!=0 || prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter)!=0) return -errno;
    return 0;
}
static void handle(void *opaque,struct sucrune_guest_thread *thread,int number,siginfo_t *info,void *native_context) {
    struct test_state *state=opaque;
    CHECK(number==SIGSYS && info!=NULL && info->si_arch==AUDIT_ARCH_AARCH64 && info->si_errno==0x7452);
    CHECK(sucrune_thread_current()==thread && pthread_self()!=0);
    unsigned char marker;CHECK(sucrune_thread_on_altstack(thread,(uintptr_t)&marker));
    (void)atomic_fetch_add(&state->signal_count,1);
    ucontext_t *context=native_context;
    if(info->si_syscall==93) sucrune_thread_exit(thread,context);
    else if(info->si_syscall==178) context->uc_mcontext.regs[0]=(uint64_t)sucrune_thread_tid(thread);
    else if(info->si_syscall==98) {
        while(atomic_load_explicit(&state->barrier,memory_order_acquire)!=0)
            (void)syscall(SYS_futex,(int *)(void *)&state->barrier,FUTEX_WAIT_PRIVATE,1,NULL,NULL,0);
        context->uc_mcontext.regs[0]=0U;
    } else _exit(159);
}
static int write_tid(void *opaque,uintptr_t address,int32_t tid) {
    struct test_state *state=opaque;
    for(size_t i=0;i<TEST_COUNT;i++) {
        if(address==(uintptr_t)&state->cases[i].parent_tid) {
            if(atomic_exchange(&state->fail_parent_write,0)!=0) return -EFAULT;
            atomic_store_explicit(&state->cases[i].parent_tid,tid,memory_order_release);return 0;
        }
        if(address==(uintptr_t)&state->cases[i].child_tid) {
            atomic_store_explicit(&state->cases[i].child_tid,tid,memory_order_release);return 0;
        }
    }
    return -EFAULT;
}
static int clear_tid(void *opaque,uintptr_t address) {
    struct test_state *state=opaque;
    for(size_t i=0;i<TEST_COUNT;i++) if(address==(uintptr_t)&state->cases[i].child_tid) {
        int32_t old=atomic_load_explicit(&state->cases[i].child_tid,memory_order_acquire);
        struct sucrune_thread_stats stats;sucrune_threads_stats(state->group,&stats);
        CHECK(stats.joined>(unsigned int)atomic_load(&state->clear_count));
        if(old>0) {errno=0;CHECK(syscall(SYS_tgkill,getpid(),old,0)<0 && errno==ESRCH);}
        atomic_store_explicit(&state->cases[i].child_tid,0,memory_order_release);
        (void)syscall(SYS_futex,(int *)(void *)&state->cases[i].child_tid,FUTEX_WAKE,1,NULL,NULL,0);
        (void)atomic_fetch_add(&state->clear_count,1);return 0;
    }
    return -EFAULT;
}
static int64_t launch(size_t index) {
    struct test_case *test=&tests.cases[index];
    /* Caller resolves the guest TP. Exercise both null (Linux startup) and
     * non-null inheritance beside musl's explicit CLONE_SETTLS. */
    uint64_t flags = (index % 3U == 0U) ? TEST_FLAGS : TEST_FLAGS & ~(uint64_t)CLONE_SETTLS;
    uintptr_t tp = (index % 3U == 1U) ? 0U : (uintptr_t)test->fake_tls;
    return sucrune_threads_clone(tests.group,flags,(uintptr_t)test->stack,
        (uintptr_t)&test->parent_tid,tp,(uintptr_t)&test->child_tid,
        UINT64_C(0x1234),&test->cpu);
}
static void verify(size_t index,int64_t tid) {
    struct test_case *test=&tests.cases[index];
    uint64_t *observed=test->stack;
    CHECK(observed[0]==0U);
    for(size_t i=1U;i<31U;i++) CHECK(observed[i]==test->cpu.regs[i]);
    CHECK(observed[32]==(index % 3U == 1U ? 0U : (uintptr_t)test->fake_tls));
    CHECK(memcmp((unsigned char *)test->stack+272U,test->cpu.vectors,sizeof(test->cpu.vectors))==0);
    CHECK(observed[98]==test->cpu.fpcr && observed[99]==test->cpu.fpsr && observed[100]==test->cpu.pstate);
    CHECK(observed[101]==(uint64_t)tid && atomic_load(&test->parent_tid)==tid && atomic_load(&test->child_tid)==0);
}
static void adapters(void) {
    ucontext_t context;memset(&context,0,sizeof(context));
    struct sucrune_signal_fpsimd *fp=(struct sucrune_signal_fpsimd *)(void *)context.uc_mcontext.__reserved;
    fp->magic=SUCRUNE_SIGNAL_FPSIMD_MAGIC;fp->size=sizeof(*fp);fp->fpsr=16U;fp->fpcr=0U;
    for(size_t i=0;i<31U;i++) context.uc_mcontext.regs[i]=UINT64_C(0x1122334400)+i;
    for(size_t i=0;i<64U;i++) fp->vectors[i]=UINT64_C(0x5566778800)+i;
    context.uc_mcontext.sp=0x1000U;context.uc_mcontext.pc=0x2000U;context.uc_mcontext.pstate=UINT64_C(0xa0001000);
    context.uc_stack.ss_sp=(void *)(uintptr_t)0x3000U;context.uc_stack.ss_size=8192U;
    struct sucrune_signal_cpu cpu;CHECK(sucrune_thread_cpu_capture(&context,&cpu)==0);
    CHECK(cpu.pstate==UINT64_C(0xa0000000) && cpu.regs[17]==UINT64_C(0x1122334411));
    cpu.regs[17]=9U;cpu.pstate=UINT64_C(0x50000000);cpu.vectors[63]=77U;
    CHECK(sucrune_thread_cpu_apply(&context,&cpu)==0);
    CHECK(context.uc_mcontext.regs[17]==9U && context.uc_mcontext.pstate==UINT64_C(0x50001000));
    CHECK(context.uc_stack.ss_sp==(void *)(uintptr_t)0x3000U && fp->vectors[63]==77U);
    cpu.pstate|=1U;CHECK(sucrune_thread_cpu_apply(&context,&cpu)==-EINVAL);cpu.pstate&=~UINT64_C(1);
    fp->size=16U;CHECK(sucrune_thread_cpu_capture(&context,&cpu)==-EINVAL);fp->size=sizeof(*fp);
    uint32_t *extra=(uint32_t *)(void *)(context.uc_mcontext.__reserved+sizeof(*fp));
    extra[0]=0x53564501U;extra[1]=16U;CHECK(sucrune_thread_cpu_capture(&context,&cpu)==0);
    extra[1]=32U;CHECK(sucrune_thread_cpu_capture(&context,&cpu)==-ENOTSUP);
    extra[0]=0x45585401U;extra[1]=32U;CHECK(sucrune_thread_cpu_capture(&context,&cpu)==-ENOTSUP);
    extra[0]=SUCRUNE_SIGNAL_FPSIMD_MAGIC;extra[1]=sizeof(*fp);CHECK(sucrune_thread_cpu_capture(&context,&cpu)==-EINVAL);
    extra[0]=0;extra[1]=0;
    CHECK(sucrune_thread_cpu_capture(NULL,&cpu)==-EINVAL);
}
int main(void) {
    adapters();
    struct sigaction handler={.sa_sigaction=sucrune_signal_entry,.sa_flags=SA_SIGINFO|SA_ONSTACK};sigfillset(&handler.sa_mask);
    CHECK(sigaction(SIGSYS,&handler,NULL)==0);
    struct sucrune_thread_callbacks callbacks={.prepare=prepare,.signal=handle,.write_tid=write_tid,.clear_tid=clear_tid};
    CHECK(sucrune_threads_create(&callbacks,&tests,&tests.group)==0);
    struct sucrune_thread_group *duplicate=NULL;CHECK(sucrune_threads_create(&callbacks,&tests,&duplicate)==-EBUSY);
    for(size_t i=0;i<TEST_COUNT;i++) {
        struct test_case *test=&tests.cases[i];test->stack_size=16384U;
        test->stack=mmap(NULL,test->stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(test->stack!=MAP_FAILED);
        test->cpu.pc=(uintptr_t)&sucrune_thread_test_guest;test->cpu.sp=(uintptr_t)test->stack;
        test->cpu.pstate=UINT64_C(0xa0000000);test->cpu.fpsr=16U;test->cpu.fpcr=0U;
        for(size_t r=0;r<31U;r++) test->cpu.regs[r]=UINT64_C(0x112233440000)+r;
        for(size_t r=0;r<64U;r++) test->cpu.vectors[r]=UINT64_C(0x556677880000)+r;
    }
    CHECK(sucrune_threads_clone(tests.group,TEST_FLAGS|17U,(uintptr_t)tests.cases[0].stack,
        4U,8U,12U,0U,&tests.cases[0].cpu)==-ENOTSUP);
    CHECK(sucrune_threads_clone(tests.group,TEST_FLAGS,1U,4U,8U,12U,0U,&tests.cases[0].cpu)==-EINVAL);
    int64_t first=launch(0U);CHECK(first>0);CHECK(sucrune_threads_join(tests.group)==0);verify(0U,first);
    atomic_store(&tests.cases[0].child_tid,12345);
    atomic_store(&tests.fail_prepare,1);CHECK(launch(0U)==-ECANCELED);CHECK(sucrune_threads_join(tests.group)==0);
    CHECK(atomic_load(&tests.cases[0].child_tid)==12345 && atomic_load(&tests.clear_count)==1);
    atomic_store(&tests.fail_parent_write,1);CHECK(launch(0U)==-EFAULT);CHECK(sucrune_threads_join(tests.group)==0);
    CHECK(atomic_load(&tests.cases[0].child_tid)==12345 && atomic_load(&tests.clear_count)==1);
    atomic_store(&tests.barrier,1);
    int64_t tids[63];for(size_t i=0;i<63U;i++) {tids[i]=launch(i);CHECK(tids[i]>0);}
    CHECK(launch(63U)==-EAGAIN);
    atomic_store_explicit(&tests.barrier,0,memory_order_release);
    (void)syscall(SYS_futex,(int *)(void *)&tests.barrier,FUTEX_WAKE_PRIVATE,INT32_MAX,NULL,NULL,0);
    CHECK(sucrune_threads_join(tests.group)==0);
    for(size_t i=0;i<63U;i++) verify(i,tids[i]);
    for(size_t i=0;i<8U;i++) {int64_t tid=launch(0U);CHECK(tid>0);CHECK(sucrune_threads_join(tests.group)==0);verify(0U,tid);}
    struct sucrune_thread_stats stats;sucrune_threads_stats(tests.group,&stats);
    CHECK(stats.live==0U && stats.peak==63U && stats.created==74U && stats.joined==74U && stats.cleanup_error==0);
    CHECK(atomic_load(&tests.clear_count)==72 && atomic_load(&tests.signal_count)==216);
    CHECK(sucrune_threads_destroy(tests.group)==0);CHECK(atomic_load(&sucrune_signal_gate_count)==0U);
    for(size_t i=0;i<TEST_COUNT;i++) CHECK(munmap(tests.cases[i].stack,tests.cases[i].stack_size)==0);
    printf("PASS guest_threads uid=%ld: adapters, GPR31/Q32/TLS, 74 joins, 63 concurrent, limits, aborts, reuse\n",(long)getuid());
    return 0;
}
#else
int main(void) {puts("ARM64 guest thread tests require an ARM64 device");return 77;}
#endif
