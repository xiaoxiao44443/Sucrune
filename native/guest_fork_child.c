#include "guest_fork_child.h"
#include "guest_local_io.h"
#include "guest_shebang.h"
#include "guest_fork_arena.h"
#include "workspace_broker.h"
#include "workspace_locks.h"
#include "guest_abi.h"
#include "guest_proc.h"
#include "linux_elf.h"
#include "pty_child.h"
#include "pty_broker.h"
#if defined(__aarch64__)
#include <errno.h>
#include "guest_devices.h"
#include "guest_landlock_decode.h"
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#include <time.h>
#include <sys/file.h>
#include <ucontext.h>
#include <unistd.h>

/* The raw pre-exec process has its own supervisor, guest disposition table,
 * emulation scratch, and descriptor snapshot even when its VM is shared. */
#define FORK_TRAP_TAG 0x5350U
#define RAW_FN __attribute__((no_stack_protector))
#define ALT_BYTES (128U*1024U)
struct child_state {
    uintptr_t gate_tls, gate_scs, supervisor_tls, supervisor_scs;
    struct sucrune_fork_launch *launch;
    int receipt, bootstrap, completion_writer, scope_lease;
    pid_t pid,parent,tid;
    uintptr_t alt_low;
    uint64_t syscalls;
    struct pollfd poll_fds[SUCRUNE_LINUX_FD_LIMIT];
    struct sucrune_request request;
    struct sucrune_response reply;
    int exec_ready;
    long exec_result;
    uintptr_t requested_clear_tid;
    struct sucrune_guest_exec image;
    unsigned char proc_stat_resource[SUCRUNE_LINUX_FD_LIMIT];
    int may_have_record_locks;
    struct sucrune_signal_cpu nested_cpu;
    uintptr_t nested_tls, nested_ctid;
    uint64_t nested_flags;
    pid_t nested_pids[SUCRUNE_PROCESS_LIMIT];
    struct sucrune_fork_launch owned;
    struct sucrune_signal_process dispositions;
    struct sucrune_guest_space initial_space, initial_fixed;
};
_Static_assert(sizeof(struct child_state)<0xa0000, "raw state exceeds reserved storage");
_Static_assert(offsetof(struct child_state,supervisor_tls)==16, "raw arena gate ABI");
static inline __attribute__((always_inline)) struct child_state *child_context(void) {
    uintptr_t sp;
    __asm__ ("mov %0,sp" : "=r"(sp));
    return (struct child_state *)(sp & ~(uintptr_t)(SUCRUNE_FORK_ARENA_BYTES-1));
}
#define active (*child_context())
extern _Noreturn void sucrune_fork_arena_enter(void *arena);
extern long sucrune_fork_raw_clone(long,void *,void (*)(void *),void *);
extern void sucrune_fork_signal_entry(int,siginfo_t *,void *);
extern void sucrune_fork_restorer(void);
extern _Noreturn void sucrune_fork_resume(uintptr_t,uint64_t,pid_t,pid_t);
static inline __attribute__((always_inline)) long raw(long n,long a,long b,long c,long d,long e,long f) {
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory","cc");
    return x0;
}
#define R0(n) raw((n),0,0,0,0,0,0)
#define R1(n,a) raw((n),(long)(a),0,0,0,0,0)
#define R2(n,a,b) raw((n),(long)(a),(long)(b),0,0,0,0)
#define R3(n,a,b,c) raw((n),(long)(a),(long)(b),(long)(c),0,0,0)
static RAW_FN _Noreturn void die(int code) { (void)R1(SYS_exit_group,code);__builtin_unreachable(); }
static RAW_FN void receipt(int result) {
    if(active.receipt<0) return;
    long wrote=raw(SYS_sendto,active.receipt,(long)&result,(long)sizeof(result),MSG_NOSIGNAL|MSG_DONTWAIT,0,0);
    if(result!=0) { (void)R1(SYS_close,active.receipt);active.receipt=-1; }
    if(wrote!=(long)sizeof(result)) die(125);
}
static RAW_FN _Noreturn void fail(long error) {receipt(error<0 ? (int)error : -EIO);die(125);}
struct directory_entry {uint64_t inode;int64_t offset;uint16_t size;unsigned char type;char name[];};
static RAW_FN int keep(int fd,int scan) {
    if(fd==active.launch->snapshot.scope_bus) return 1;
    if(fd==scan || fd==active.receipt || fd==active.completion_writer || fd==active.launch->broker || fd==1 || fd==2) return 1;
    for(unsigned int i=0;i<active.launch->fd_limit;i++) if(active.launch->aliases[i]==fd) return 1;
    return 0;
}
static RAW_FN int clean_descriptors(void) {
    long scan=raw(SYS_openat,AT_FDCWD,(long)"/proc/self/fd",O_DIRECTORY|O_RDONLY|O_CLOEXEC,0,0,0);
    if(scan<0) return (int)scan;
    union {uint64_t alignment;unsigned char bytes[4096];} buffer;
    int error=0;
    for(int pass=0;pass<2 && error==0;pass++) {
        unsigned int seen=0;
        for(;;) {
            long got=R3(SYS_getdents64,scan,buffer.bytes,sizeof(buffer.bytes));
            if(got<=0) {error=(int)got;break;}
            size_t offset=0;
            while(offset<(size_t)got) {
                size_t header=offsetof(struct directory_entry,name);
                if((size_t)got-offset<=header) {error=-EPROTO;break;}
                const struct directory_entry *entry=(const void *)(buffer.bytes+offset);
                size_t size=entry->size;
                if(size<=header || size>(size_t)got-offset || ++seen>16384U) {error=-EOVERFLOW;break;}
                int fd=0,numeric=1;size_t i=0;
                for(;i<size-header && entry->name[i]!='\0';i++) {
                    unsigned char digit=(unsigned char)entry->name[i];
                    if(digit<'0' || digit>'9' || fd>(INT_MAX-(int)(digit-'0'))/10) {numeric=0;break;}
                    fd=fd*10+(int)(digit-'0');
                }
                if(i==size-header) {error=-EPROTO;break;}
                if(i>0U && numeric && !keep(fd,(int)scan)) (void)R1(SYS_close,fd);
                offset+=size;
            }
            if(error!=0) break;
        }
        if(pass==0 && !error) {long rc=R3(SYS_lseek,scan,0,SEEK_SET);if(rc<0) error=(int)rc;}
    }
    (void)R1(SYS_close,scan);return error;
}
static RAW_FN int allowed(uintptr_t addr,size_t size,int write) {
    const struct sucrune_process_snapshot *s=&active.launch->snapshot;
    return sucrune_space_access(s->space,addr,size,write) || sucrune_space_access(s->fixed_space,addr,size,write);
}
static RAW_FN int executable(uintptr_t pc) {
    const struct sucrune_process_snapshot *s=&active.launch->snapshot;
    const struct sucrune_guest_space *spaces[2]={s->space,s->fixed_space};
    if((pc&3U)!=0U) return 0;
    for(unsigned int i=0;i<2U;i++) for(size_t j=0;j<spaces[i]->count;j++) {
        const struct sucrune_space_vma *v=&spaces[i]->areas[j];
        if((v->protection&PROT_EXEC)!=0 && pc>=v->start && pc-v->start<v->length && v->length-(pc-v->start)>=4U) return 1;
    }
    return 0;
}
/* Preserve the kernel frame layout, alt stack and kernel signal mask. Write
 * only the architectural fields in our normalized clone snapshot. Explicit
 * volatile copies keep this post-fork path independent of libc memcpy/TLS. */
static RAW_FN int fork_cpu(ucontext_t *uc,struct sucrune_signal_cpu *cpu,int capture) {
    unsigned char *base=uc->uc_mcontext.__reserved;
    size_t size=sizeof(uc->uc_mcontext.__reserved),offset=0;
    struct sucrune_signal_fpsimd *fp=NULL;
    int terminated=0;
    while(offset+8U<=size) {
        uint32_t *header=(void *)(base+offset);
        if(header[0]==0 && header[1]==0) {terminated=1;break;}
        if(header[1]<16U || (header[1]&15U)!=0U || header[1]>size-offset) return -EINVAL;
        if(header[0]==SUCRUNE_SIGNAL_FPSIMD_MAGIC && header[1]==sizeof(*fp) && fp==NULL) fp=(void *)header;
        else if(header[0]==UINT32_C(0x45535201) && header[1]==16U) { /* ESR */ }
        else if(header[0]==UINT32_C(0x53564501) && header[1]==16U && *(uint16_t *)(void *)(base+offset+10U)==0) { /* inactive SVE */ }
        else return -ENOTSUP;
        offset+=header[1];
    }
    if(!terminated || fp==NULL) return -EINVAL;
    if(capture) {
        for(unsigned int i=0;i<31U;i++) ((volatile uint64_t *)cpu->regs)[i]=uc->uc_mcontext.regs[i];
        cpu->sp=uc->uc_mcontext.sp;cpu->pc=uc->uc_mcontext.pc;
        cpu->pstate=uc->uc_mcontext.pstate&SUCRUNE_SIGNAL_NZCV;
        cpu->fpsr=fp->fpsr;cpu->fpcr=fp->fpcr;
        for(unsigned int i=0;i<64U;i++) ((volatile uint64_t *)cpu->vectors)[i]=fp->vectors[i];
        return 0;
    }
    if((cpu->pstate&~SUCRUNE_SIGNAL_NZCV)!=0U) return -EINVAL;
    for(unsigned int i=0;i<31U;i++) ((volatile uint64_t *)uc->uc_mcontext.regs)[i]=cpu->regs[i];
    uc->uc_mcontext.regs[0]=0;
    uc->uc_mcontext.sp=cpu->sp;uc->uc_mcontext.pc=cpu->pc;
    uc->uc_mcontext.pstate=(uc->uc_mcontext.pstate&~SUCRUNE_SIGNAL_NZCV)|cpu->pstate;
    fp->fpcr=cpu->fpcr;fp->fpsr=cpu->fpsr;
    for(unsigned int i=0;i<64U;i++) ((volatile uint64_t *)fp->vectors)[i]=cpu->vectors[i];
    return 0;
}
static RAW_FN int local_fd(uint64_t guestfd) {
    return guestfd<active.launch->fd_limit ? active.launch->aliases[guestfd] : -1;
}
static RAW_FN void bytes_copy(void *to,const void *from,size_t count) {
    volatile unsigned char *dst=to;
    const volatile unsigned char *src=from;
    for(size_t i=0;i<count;i++) dst[i]=src[i];
}
static RAW_FN long guest_string(uintptr_t addr,char *dest,size_t size) {
    size_t checked=0;
    const size_t page=active.launch->snapshot.space->page_size;
    for(size_t i=0;i<size;i++) {
        if(i==checked) {
            if(addr>UINTPTR_MAX-i) return -EFAULT;
            /* VMAs are page-aligned. Validate each page as we reach it, without
             * reading the next page when the string ends at its boundary. */
            size_t span=page-((addr+i)&(page-1U));
            if(span>size-i) span=size-i;
            if(!allowed(addr+i,span,0)) return -EFAULT;
            checked=i+span;
        }
        dest[i]=*(volatile char *)(addr+i);
        if(dest[i]=='\0') return (long)(i+1U);
    }
    return -ENAMETOOLONG;
}
static RAW_FN void begin_request(unsigned int op) {
    struct sucrune_request *r=&active.request;
    r->magic=SUCRUNE_BROKER_MAGIC;r->operation=op;r->size=0;r->reserved=0;
    for(unsigned int i=0;i<4U;i++) r->args[i]=0;
}
static RAW_FN char *decimal(char text[16],int number);
/* Called from the raw supervisor or the raw signal path. Use no libc I/O,
 * allocation or TLS. The named reason and virtual FD are safe to expose. */
static RAW_FN void child_refusal(const char *reason,size_t length,int fd) {
    if (!active.launch->snapshot.trace_faults) return;
    char number[16];
    char *value=fd<0 ? "-" : decimal(number,fd);
    struct iovec line[]={{"[sucrune-fork] unsupported ",sizeof("[sucrune-fork] unsupported ")-1U},
        {(void *)reason,length},{" guest_fd=",sizeof(" guest_fd=")-1U},{value,fd<0 ? 1U : (size_t)(number+15-value)},{"\n",1U}};
    (void)R3(SYS_writev,STDERR_FILENO,line,sizeof(line)/sizeof(line[0]));
}
#define CHILD_REFUSAL(reason,fd) child_refusal(reason,sizeof(reason)-1U,fd)
static RAW_FN long transact_right(int *received) {
    struct sucrune_request *r=&active.request;
    struct sucrune_response *response=&active.reply;
    int socket=active.launch->broker;
    size_t bytes=offsetof(struct sucrune_request,data)+r->size;
    long sent;
    do {sent=raw(SYS_sendto,socket,(long)r,(long)bytes,MSG_NOSIGNAL,0,0);} while(sent==-EINTR);
    if(sent!=(long)bytes) return sent<0 ? sent : -EIO;
    struct iovec iov={.iov_base=response,.iov_len=sizeof(*response)};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
    union {struct cmsghdr alignment;unsigned char bytes[CMSG_SPACE(sizeof(int))];} control;
    if(received!=NULL) {*received=-1;message.msg_control=control.bytes;message.msg_controllen=sizeof(control.bytes);}
    long got;
    do {got=R3(SYS_recvmsg,socket,&message,MSG_CMSG_CLOEXEC);} while(got==-EINTR);
    if(got<0) {(void)R2(SYS_shutdown,socket,SHUT_RDWR);return got;}
    /* Linux can fit two int rights in the alignment padding for one right.
     * Explicitly close every delivered FD whenever validation fails. */
    int rights[2]={-1,-1};size_t count=0;
    int bad=0;
    if(received!=NULL && message.msg_controllen) {
        struct cmsghdr *c=CMSG_FIRSTHDR(&message);
        if(c==NULL || c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS ||
                c->cmsg_len<CMSG_LEN(sizeof(int)) || c->cmsg_len>message.msg_controllen) bad=1;
        else {
            size_t payload=c->cmsg_len-CMSG_LEN(0);
            count=payload/sizeof(int);
            if(count>2U) die(125);
            bytes_copy(rights,CMSG_DATA(c),count*sizeof(int));
            if(payload!=sizeof(int) || message.msg_controllen>CMSG_SPACE(payload)) bad=1;
        }
    }
    if(bad || got<(long)offsetof(struct sucrune_response,data) || (message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0 ||
        response->magic!=SUCRUNE_BROKER_MAGIC || response->size>SUCRUNE_IO_LIMIT ||
        got!=(long)(offsetof(struct sucrune_response,data)+response->size) ||
        (received!=NULL && count!=(response->result>=0 ? 1U : 0U))) {
        for(size_t i=0;i<count;i++) (void)R1(SYS_close,rights[i]);
        (void)R2(SYS_shutdown,socket,SHUT_RDWR);return -EPROTO;
    }
    if(count==1U) *received=rights[0];
    return response->result;
}
static RAW_FN long transact(void) {return transact_right(NULL);}

static RAW_FN int nested_slot(pid_t pid) {
    for(unsigned int i=0;i<SUCRUNE_PROCESS_LIMIT;i++) if(active.nested_pids[i]==pid) return (int)i;
    return -1;
}
/* Run only on the baseline supervisor. A filtered guest thread cannot do
 * this fork itself: the new supervisor must be able to exec a fresh runner. */
static RAW_FN long nested_fork_launch(void) {
    int slot=nested_slot(0);
    if(slot<0) return -EAGAIN;
    int channel[2];
    long result=raw(SYS_socketpair,AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,(long)channel,0,0);
    if(result<0) return result;
    int broker=-1;
    int completion[2]={-1,-1};
    void *arena=NULL;
    begin_request(SUCRUNE_BROKER_FORK_SESSION);
    result=transact_right(&broker);
    if(result==-EOPNOTSUPP) CHILD_REFUSAL("nested-broker-session",-1);
    if(result==0) {
        pid_t parent=active.pid;
        struct sucrune_fork_launch launch;
        bytes_copy(&launch,active.launch,sizeof(launch));
        bytes_copy(&launch.snapshot.cpu,&active.nested_cpu,sizeof(active.nested_cpu));
        launch.snapshot.tls=active.nested_tls;
        launch.snapshot.child_tid=active.nested_ctid;
        launch.snapshot.flags=active.nested_flags;
        bytes_copy(launch.proc_stat_resource,active.proc_stat_resource,sizeof(launch.proc_stat_resource));
        launch.broker=broker;
        launch.parent_group=(pid_t)R1(SYS_getpgid,0);
        launch.parent_session=(pid_t)R1(SYS_getsid,0);
        if((launch.snapshot.flags&CLONE_VFORK)!=0U) {
            result=R2(SYS_pipe2,completion,O_CLOEXEC);
            if(result==0) {
                result=sucrune_vfork_child_start(&launch,channel[1],parent,completion[1],&arena);
                (void)R1(SYS_close,completion[1]);
            }
        } else {
            result=raw(SYS_clone,SIGCHLD,0,0,0,0,0);
            if(result==0) sucrune_fork_child_start(&launch,channel[1],parent);
        }
    }
    if(broker>=0) (void)R1(SYS_close,broker);
    (void)R1(SYS_close,channel[1]);
    if(result>0) {
        pid_t child=(pid_t)result;
        struct pollfd pollfd={.fd=channel[0],.events=POLLIN};
        const struct timespec timeout={.tv_sec=2};
        int reply=0;
        long ready=raw(SYS_ppoll,(long)&pollfd,1,(long)&timeout,0,8,0);
        long got=ready>0 ? raw(SYS_recvfrom,channel[0],(long)&reply,sizeof(reply),MSG_TRUNC|MSG_DONTWAIT,0,0) : ready;
        if(got==(long)sizeof(reply) && reply==0) active.nested_pids[slot]=child;
        else {
            (void)R2(SYS_kill,child,SIGKILL);
            long waited;
            do {waited=raw(SYS_wait4,child,0,0,0,0,0);} while(waited==-EINTR);
            if(waited!=child) die(125);
            result=got<0 ? got : ready==0 ? -ETIMEDOUT : got==(long)sizeof(reply) && reply<0 ? reply : -EIO;
        }
    }
    (void)R1(SYS_close,channel[0]);
    if(completion[0]>=0) {
        if(arena) {
            char byte;
            long n;
            do {n=R3(SYS_read,completion[0],&byte,1);} while(n==-EINTR);
            if(n!=0) die(125);
            sucrune_vfork_release_arena(arena);
        }
        (void)R1(SYS_close,completion[0]);
    }
    return result;
}
static RAW_FN long nested_clone(ucontext_t *uc,uintptr_t guest_tls) {
    const uint64_t *args=(const uint64_t *)uc->uc_mcontext.regs;
    uint64_t known=UINT64_C(255)|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID;
    if((args[0]&(CLONE_VM|CLONE_VFORK))==(CLONE_VM|CLONE_VFORK) && active.completion_writer<0)
        known|=CLONE_VM|CLONE_VFORK;
    if((args[0]&255U)!=SIGCHLD || (args[0]&~known)!=0U) {
        CHILD_REFUSAL("nested-clone-flags",-1);return -EOPNOTSUPP;
    }
    if((args[0]&CLONE_PARENT_SETTID) && ((args[2]&3U) || !allowed(args[2],4U,1))) return -EFAULT;
    if((args[0]&(CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID)) && ((args[4]&3U) || !allowed(args[4],4U,1))) return -EFAULT;
    int error=fork_cpu(uc,&active.nested_cpu,1);
    if(error) return error;
    if(args[1]) active.nested_cpu.sp=args[1];
    uintptr_t sp=active.nested_cpu.sp;
    if((sp&15U) || sp<16U || !allowed(sp-16U,16U,1)) return -EFAULT;
    active.nested_flags=args[0];active.nested_tls=guest_tls;active.nested_ctid=args[4];
    __atomic_store_n(&active.exec_ready,2,__ATOMIC_RELEASE);
    (void)R3(SYS_futex,&active.exec_ready,FUTEX_WAKE_PRIVATE,1);
    while(__atomic_load_n(&active.exec_ready,__ATOMIC_ACQUIRE))
        (void)raw(SYS_futex,(long)&active.exec_ready,FUTEX_WAIT_PRIVATE,2,0,0,0);
    long result=active.exec_result;
    if(result>0 && (args[0]&CLONE_PARENT_SETTID)) *(int32_t *)(uintptr_t)args[2]=(int32_t)result;
    return result;
}
static RAW_FN long nested_wait(const uint64_t *args) {
    int pid=(int32_t)args[0];
    if(pid!= -1 && (pid<=0 || nested_slot(pid)<0)) return -ECHILD;
    if(args[2]&~(uint64_t)(WNOHANG|WUNTRACED|WCONTINUED)) return -EINVAL;
    if((args[1] && !allowed(args[1],sizeof(int),1)) ||
       (args[3] && !allowed(args[3],sizeof(struct rusage),1))) return -EFAULT;
    int status=0;
    struct rusage usage;
    long result=raw(SYS_wait4,pid,(long)&status,(long)args[2],args[3] ? (long)&usage : 0,0,0);
    if(result>0) {
        int slot=nested_slot((pid_t)result);
        if(slot<0) return -ECHILD;
        if(WIFEXITED(status) || WIFSIGNALED(status)) active.nested_pids[slot]=0;
        if(args[1]) bytes_copy((void *)(uintptr_t)args[1],&status,sizeof(status));
        if(args[3]) bytes_copy((void *)(uintptr_t)args[3],&usage,sizeof(usage));
    }
    return result;
}
static RAW_FN long copy_project_stat(uintptr_t destination) {
    struct sucrune_arm64_stat st;
    if(active.reply.size!=sizeof(st)) return -EPROTO;
    bytes_copy(&st,active.reply.data,sizeof(st));
    sucrune_project_stat_owner(&st,&active.launch->snapshot.owner);
    bytes_copy((void *)destination,&st,sizeof(st));
    return 0;
}
static RAW_FN long child_sleep(int op,const uint64_t *a) {
    int clock=op==115 ? (int)a[0] : CLOCK_MONOTONIC;
    uint64_t flags=op==115 ? a[1] : 0;
    if(clock!=CLOCK_MONOTONIC && clock!=CLOCK_REALTIME && clock!=CLOCK_BOOTTIME) return -EINVAL;
    if((flags&~(uint64_t)TIMER_ABSTIME)!=0) return -EINVAL;
    uintptr_t input=(uintptr_t)a[op==115 ? 2 : 0];
    uintptr_t remaining=flags==TIMER_ABSTIME ? 0 : (uintptr_t)a[op==115 ? 3 : 1];
    struct timespec delay,rem={0};
    if(!allowed(input,sizeof(delay),0) || (remaining && !allowed(remaining,sizeof(rem),1))) return -EFAULT;
    bytes_copy(&delay,(const void *)input,sizeof(delay));
    if(delay.tv_sec<0 || delay.tv_nsec<0 || delay.tv_nsec>=1000000000L) return -EINVAL;
    if(flags==TIMER_ABSTIME) {
        struct timespec now;
        long rc=R2(SYS_clock_gettime,clock,&now);
        if(rc<0) return rc;
        if(delay.tv_sec>now.tv_sec) {
            uint64_t delta=(uint64_t)delay.tv_sec-(uint64_t)now.tv_sec;
            if(delta>60U || (delta==60U && delay.tv_nsec>now.tv_nsec)) return -EINVAL;
        }
    } else if(delay.tv_sec>60) return -EINVAL;
    long result=raw(SYS_clock_nanosleep,clock,(long)flags,(long)&delay,(long)&rem,0,0);
    if(result==-EINTR && remaining) bytes_copy((void *)remaining,&rem,sizeof(rem));
    return result;
}
static RAW_FN int file_handle(uint64_t fd) {return fd<active.launch->fd_limit ? active.launch->handles[fd] : -1;}
/* Raw fork continuations (including ash NOEXEC applets) use the same
 * project broker as the primary runner. Guest descriptor numbers never
 * identify broker resources, even when the numeric values coincide. */
static RAW_FN int is_net_dir(uint64_t dirfd) {
    return local_fd(dirfd)>=0 &&
           active.proc_stat_resource[active.launch->metadata[dirfd].resource]==SUCRUNE_PROC_NET_DIR;
}
static RAW_FN long net_dir_path(uint64_t dirfd,char *path,long size) {
    if(size<=0 || path[0]=='/' || !is_net_dir(dirfd)) return size;
    return sucrune_proc_net_at(path,(size_t)size,SUCRUNE_PATH_LIMIT);
}
static RAW_FN long add_at_path(uint64_t dirfd,uintptr_t guest,int index,int mutating) {
    size_t offset=active.request.size;
    if(offset>sizeof(active.request.data)-SUCRUNE_PATH_LIMIT) return -ENAMETOOLONG;
    char *path=(char *)active.request.data+offset;
    long size=net_dir_path(dirfd,path,guest_string(guest,path,SUCRUNE_PATH_LIMIT));
    if(size<0) return size;
    if(sucrune_proc_path(path)) {
        if(mutating) return -EROFS;
        if(!sucrune_proc_self_stat(path,active.pid) && !sucrune_proc_system_file(path) && !sucrune_proc_is_net_dir(path)) return -ENOENT;
    }
    int handle=AT_FDCWD;
    if(path[0]!='/' && (int32_t)dirfd!=AT_FDCWD) {
        handle=file_handle(dirfd);
        if(handle<0) return local_fd(dirfd)<0 ? -EBADF : -ENOTDIR;
    }
    active.request.args[index]=handle;
    active.request.size+=(uint32_t)size;
    return 0;
}
static RAW_FN int free_slot(unsigned int from) {
    for(unsigned int i=from;i<active.launch->fd_limit;i++) if(local_fd(i)<0 && file_handle(i)<0) return (int)i;
    return -EMFILE;
}
static RAW_FN int new_resource(void) {
    uint64_t used[SUCRUNE_LINUX_FD_LIMIT / 64U] = {0};
    for (unsigned int i = 0; i < active.launch->fd_limit; i++) {
        int id = active.launch->metadata[i].resource;
        if (id < 0) continue;
        if ((unsigned int)id >= active.launch->fd_limit) die(125);
        used[(unsigned int)id / 64U] |= UINT64_C(1) << ((unsigned int)id % 64U);
    }
    for (unsigned int word = 0; word < active.launch->fd_limit / 64U; word++)
        if (used[word] != UINT64_MAX) return (int)(word * 64U) + __builtin_ctzll(~used[word]);
    return -EMFILE;
}
static RAW_FN void record_new(int slot,int kind,int flags,int pty,int number) {
    int id=new_resource();
    if(id<0) die(125);
    active.proc_stat_resource[id]=0;
    active.launch->udp_resource[id]=0;
    active.launch->metadata[slot]=(struct sucrune_exec_fd){.resource=id,.kind=kind,
        .status_flags=flags,.pty_kind=pty,.pty_number=number,.local_alias=-1,.broker_handle=-1};
}
static RAW_FN long close_guest(unsigned int fd) {
    int host=local_fd(fd), handle=file_handle(fd);
    if(host<0 && handle<0) return -EBADF;
    struct sucrune_exec_fd metadata=active.launch->metadata[fd];
    active.launch->aliases[fd]=-1;active.launch->handles[fd]=-1;active.launch->fd_flags[fd]=0;
    active.launch->metadata[fd].resource=-1;
    active.launch->metadata[fd].network_token=0;
    if(host>=0) {
        long result=R1(SYS_close,host);
        if(metadata.network_token!=0U) {
            for(unsigned int i=0;i<active.launch->fd_limit;i++)
                if(active.launch->metadata[i].network_token==metadata.network_token) return result;
            begin_request(SUCRUNE_NET_RELEASE);active.request.args[0]=(int64_t)metadata.network_token;
            active.request.args[3]=SUCRUNE_NET_VERSION;
            long dropped=transact();
            if(dropped==0 && (active.reply.size!=SUCRUNE_NET_REPLY_HEADER ||
                sucrune_net_u32(active.reply.data)!=SUCRUNE_NET_VERSION || sucrune_net_u32(active.reply.data+4U)!=0U))
                dropped=-EPROTO;
            if(result==0) result=dropped;
        }
        if(metadata.pty_kind==SUCRUNE_PTY_MASTER) {
            for(unsigned int i=0;i<active.launch->fd_limit;i++) if(active.launch->metadata[i].resource==metadata.resource) return result;
            begin_request(SUCRUNE_PTY_MASTER_DROP);active.request.args[0]=metadata.pty_number;
            long dropped=transact();
            if(result==0) result=dropped;
        }
        return result;
    }
    for(unsigned int i=0;i<active.launch->fd_limit;i++) if(file_handle(i)==handle) {
        if (!active.may_have_record_locks || sucrune_pty_slave_handle(handle)) return 0;
        begin_request(SUCRUNE_BROKER_RECORD_CLOSE);active.request.args[0]=handle;return transact();
    }
    begin_request(57);active.request.args[0]=handle;return transact();
}
static RAW_FN long duplicate(uint64_t source,uint64_t target,unsigned int flags,int replace) {
    int original=local_fd(source),handle=file_handle(source);
    if(original<0 && handle<0) return -EBADF;
    if(target>=active.launch->fd_limit) return replace ? -EBADF : -EINVAL;
    unsigned int slot=(unsigned int)target;
    if(replace && source==target) return -EINVAL;
    if(!replace) {
        int available=free_slot(slot);if(available<0) return available;slot=(unsigned int)available;
    }
    long newfd=-1;
    if(original>=0) {newfd=R3(SYS_fcntl,original,F_DUPFD_CLOEXEC,3);if(newfd<0) return newfd;}
    if(local_fd(slot)>=0 || file_handle(slot)>=0) (void)close_guest(slot);
    active.launch->aliases[slot]=(int)newfd;active.launch->handles[slot]=handle;active.launch->fd_flags[slot]=flags;
    active.launch->metadata[slot]=active.launch->metadata[source];
    return (long)slot;
}
static RAW_FN int pty_lookup(void *unused,unsigned int fd,struct sucrune_pty_endpoint *out) {
    (void)unused;
    if(fd>=active.launch->fd_limit || active.launch->metadata[fd].resource<0) return -EBADF;
    const struct sucrune_exec_fd *meta=&active.launch->metadata[fd];
    if(meta->pty_kind==0 || local_fd(fd)<0) return -ENOTTY;
    out->fd=local_fd(fd);out->kind=(enum sucrune_pty_kind)meta->pty_kind;out->number=meta->pty_number;
    return 0;
}
static RAW_FN int pty_publish(void *unused,int alias,enum sucrune_pty_kind kind,int number,uint64_t flags) {
    (void)unused;
    int slot=free_slot(0);
    if(slot<0) return slot;
    record_new(slot,SUCRUNE_FD_LOCAL,(int)(flags&(O_NONBLOCK|O_ACCMODE)),(int)kind,number);
    active.launch->aliases[slot]=alias;active.launch->fd_flags[slot]=(flags&O_CLOEXEC)!=0U;
    return slot;
}
static RAW_FN int pty_copy(void *unused,uintptr_t guest,void *host,size_t size,int write) {
    (void)unused;
    if(!allowed(guest,size,write)) return -EFAULT;
    if(write) bytes_copy((void *)guest,host,size);
    else bytes_copy(host,(const void *)guest,size);
    return 0;
}
static RAW_FN int own_group(void *unused,int group) {
    (void)unused;
    if(group<=0) return 0;
    if(R1(SYS_getpgid,0)==group) return 1;
    /* A snapshot of a sibling PID is not a live ownership proof. Only allow
     * the original parent's own group while that same parent still leads it
     * in our session. PDEATHSIG is installed before running guest code. */
    return group==active.parent && group==active.launch->parent_group &&
        R0(SYS_getppid)==active.parent && R1(SYS_getsid,0)==active.launch->parent_session &&
        R1(SYS_getsid,active.parent)==active.launch->parent_session && R1(SYS_getpgid,active.parent)==group;
}
static RAW_FN long join_sibling_group(int32_t pgid) {
    int32_t result;
    long n;
    do { n=raw(SYS_sendto,active.receipt,(long)&pgid,sizeof(pgid),MSG_NOSIGNAL,0,0); } while(n==-EINTR);
    if(n!=(long)sizeof(pgid)) return n<0 ? n : -EPROTO;
    do { n=raw(SYS_recvfrom,active.receipt,(long)&result,sizeof(result),MSG_TRUNC,0,0); } while(n==-EINTR);
    return n!=(long)sizeof(result) ? (n<0 ? n : -EPROTO) : result;
}
static const struct sucrune_pty_child_ops pty_ops={.raw=raw,.lookup=pty_lookup,.publish=pty_publish,
    .copy=pty_copy,.allow_group=own_group};
static RAW_FN long open_managed_tty(int master,int number,uint64_t flags) {
    int native_flags;
    int error=sucrune_pty_open_flags(flags,&native_flags);
    if(error!=0) return error;
    int slot=free_slot(0);if(slot<0) return slot;
    int right=-1;
    begin_request(master ? SUCRUNE_PTY_MASTER_OPEN : SUCRUNE_PTY_SLAVE_OPEN);
    if(master) active.request.args[0]=(int64_t)flags;
    else {active.request.args[0]=number;active.request.args[1]=(int64_t)flags;}
    long result=master ? transact_right(&right) : transact();
    if(result<0) return result;
    if(!master) {
        if(!sucrune_pty_slave_handle(result)) return -EPROTO;
        record_new(slot,SUCRUNE_FD_BROKER,native_flags,SUCRUNE_PTY_SLAVE,number);
        active.launch->handles[slot]=(int)result;
    } else {
        int actual=-1;
        if(right<3 || result>INT_MAX || R3(SYS_ioctl,right,TIOCGPTN,&actual)<0 || actual!=result) {
            if(right>=0) (void)R1(SYS_close,right);
            (void)R2(SYS_shutdown,active.launch->broker,SHUT_RDWR);return -EPROTO;
        }
        record_new(slot,SUCRUNE_FD_LOCAL,native_flags,SUCRUNE_PTY_MASTER,actual);
        active.launch->aliases[slot]=right;
    }
    active.launch->fd_flags[slot]=(flags&O_CLOEXEC)!=0U;
    return slot;
}
static RAW_FN long borrow_tty_master(int handle,int *number) {
    int right=-1;
    begin_request(SUCRUNE_PTY_CONTROL_MASTER);active.request.args[0]=handle;
    long result=transact_right(&right);
    if(result<0) return result;
    int actual=-1;
    if(right<3 || result>INT_MAX || R3(SYS_ioctl,right,TIOCGPTN,&actual)<0 || actual!=result) {
        if(right>=0) (void)R1(SYS_close,right);
        (void)R2(SYS_shutdown,active.launch->broker,SHUT_RDWR);return -EPROTO;
    }
    *number=actual;
    return right;
}
static RAW_FN long controlling_alias(uint64_t flags) {
    int native_flags;
    int err=sucrune_pty_open_flags(flags,&native_flags);
    if(err<0) return err;
    if(free_slot(0)<0) return -EMFILE;
    long sid=R1(SYS_getsid,0);if(sid<0) return sid;
    for(unsigned int i=0;i<active.launch->fd_limit;i++) {
        int handle=file_handle(i);
        if(!sucrune_pty_slave_handle(handle)) continue;
        int number=-1,owner=-1;
        long master=borrow_tty_master(handle,&number);
        if(master<0) {if(master==-EIO) continue;return master;}
        long checked=R3(SYS_ioctl,master,TIOCGSID,&owner);
        (void)R1(SYS_close,master);
        if(checked!=0 || owner!=sid) continue;
        long alias=raw(SYS_openat,AT_FDCWD,(long)"/dev/tty",native_flags|O_NOCTTY,0,0,0);
        if(alias<0) return alias;
        int slot=pty_publish(NULL,(int)alias,SUCRUNE_PTY_SLAVE,number,flags);
        if(slot<0) (void)R1(SYS_close,alias);
        return slot;
    }
    return sucrune_pty_child_open(&pty_ops,"/dev/tty",flags);
}
static RAW_FN long open_tty_path(const char *path,uint64_t flags) {
    /* All accepted paths already matched the exact PTY namespace. */
    if(path[5]=='p' && path[6]=='t' && path[7]=='m') return open_managed_tty(1,0,flags);
    if(path[5]=='t') return controlling_alias(flags);
    const char *p=path+9;
    if(!*p || (*p=='0' && p[1])) return -ENOENT;
    int number=0;
    while(*p) {
        int digit=*p++-'0';
        if(digit<0 || digit>9 || number>(INT_MAX-digit)/10) return -ENOENT;
        number=number*10+digit;
    }
    return open_managed_tty(0,number,flags);
}
static RAW_FN long proxy_tty_ioctl(int handle,uint64_t command,uint64_t arg) {
    struct sucrune_pty_request plan;
    int error=sucrune_pty_plan(SUCRUNE_PTY_SLAVE,command,&plan);
    if(error) return error;
    if(plan.size>SUCRUNE_PTY_BUFFER) return -EIO;
    if(command==TIOCSCTTY || command==TIOCGSID || command==TIOCGPGRP || command==TIOCSPGRP) {
        int value=0,number=-1;
        if(command==TIOCSCTTY) {
            if(arg!=0U || R1(SYS_getsid,0)!=active.pid) return -EPERM;
        } else {
            if(!allowed((uintptr_t)arg,sizeof(value),command!=TIOCSPGRP)) return -EFAULT;
            if(command==TIOCSPGRP) {
                bytes_copy(&value,(const void *)(uintptr_t)arg,sizeof(value));
                if(!own_group(NULL,value)) return -EPERM;
            }
        }
        long master=borrow_tty_master(handle,&number);
        if(master<0) return master;
        long result=R3(SYS_ioctl,master,command,command==TIOCSCTTY ? 0 : (long)&value);
        (void)R1(SYS_close,master);
        if(result==0 && (command==TIOCGSID || command==TIOCGPGRP))
            bytes_copy((void *)(uintptr_t)arg,&value,sizeof(value));
        return result;
    }
    begin_request(SUCRUNE_PTY_IOCTL);
    active.request.args[0]=handle;active.request.args[1]=(int64_t)command;
    if(plan.argument==SUCRUNE_PTY_SCALAR) active.request.args[2]=(int64_t)arg;
    else if(plan.argument==SUCRUNE_PTY_GET || plan.argument==SUCRUNE_PTY_SET) {
        if(!allowed((uintptr_t)arg,plan.size,plan.argument==SUCRUNE_PTY_GET)) return -EFAULT;
        if(plan.argument==SUCRUNE_PTY_SET) {
            bytes_copy(active.request.data,(const void *)(uintptr_t)arg,plan.size);
            active.request.size=(uint32_t)plan.size;
        }
    } else return -ENOTSUP;
    long result=transact();
    if(result<0) return result;
    if(result!=0 || active.reply.size!=(plan.argument==SUCRUNE_PTY_GET ? (uint32_t)plan.size : 0U)) return -EPROTO;
    if(plan.argument==SUCRUNE_PTY_GET) bytes_copy((void *)(uintptr_t)arg,active.reply.data,plan.size);
    return 0;
}
static RAW_FN long add_exec_string(uintptr_t guest,size_t limit,int path) {
    struct sucrune_guest_exec *image=&active.image;
    size_t available=sizeof(image->text)-image->text_size;
    if(!available) return -E2BIG;
    long count=guest_string(guest,(char *)image->text+image->text_size,available<limit ? available : limit);
    if(count<0) return count==-ENAMETOOLONG && (!path || available<limit) ? -E2BIG : count;
    if(path && count==1) return -ENOENT;
    image->text_size+=(uint32_t)count;
    return 0;
}
static RAW_FN long add_exec_vector(uintptr_t vector,uint32_t limit,uint32_t *count) {
    *count=0;
    if(vector==0) return 0;
    for(unsigned int i=0;i<=limit;i++) {
        size_t offset=(size_t)i*sizeof(uintptr_t);
        if(vector>UINTPTR_MAX-offset || !allowed(vector+offset,sizeof(uintptr_t),0)) return -EFAULT;
        uintptr_t pointer;
        bytes_copy(&pointer,(const void *)(vector+offset),sizeof(pointer));
        if(!pointer) return 0;
        if(i==limit) return -E2BIG;
        long result=add_exec_string(pointer,SUCRUNE_GUEST_EXEC_TEXT,0);
        if(result<0) return result;
        (*count)++;
    }
    return -E2BIG;
}
static RAW_FN long request_exec(const uint64_t *args) {
    struct sucrune_guest_exec *image=&active.image;
    if(active.launch->snapshot.runner==NULL) {CHILD_REFUSAL("missing-runner",-1);return -ENOTSUP;}
    /* The fresh runner cannot adopt this continuation's wait table. Retain
     * ownership until wait4 collects the children, then allow exec to retry. */
    for(unsigned int i=0;i<SUCRUNE_PROCESS_LIMIT;i++) if(active.nested_pids[i]!=0) {
        CHILD_REFUSAL("live-children",-1);return -EOPNOTSUPP;
    }
    if(active.launch->snapshot.exec_depth>=32U) return -ELOOP;
    image->text_size=0;
    long result=add_exec_string((uintptr_t)args[0],SUCRUNE_PATH_LIMIT,1);
    if(result==0) result=add_exec_vector((uintptr_t)args[1],SUCRUNE_GUEST_EXEC_ARGS,&image->argc);
    /* Linux supplies a single empty argv[0] for an empty argument vector. */
    if(result==0 && image->argc==0U) {
        if(image->text_size==sizeof(image->text)) return -E2BIG;
        image->text[image->text_size++]=0;image->argc=1;
    }
    if(result==0) result=add_exec_vector((uintptr_t)args[2],SUCRUNE_GUEST_EXEC_ENV,&image->envc);
    if(result<0) return result;
    /* Only this raw worker enters guest code. Suspend it with every argument
     * and descriptor stable while the baseline-filter supervisor preflights.
     * A successful host exec replaces both threads. A failure wakes this one. */
    __atomic_store_n(&active.exec_ready,1,__ATOMIC_RELEASE);
    (void)R3(SYS_futex,&active.exec_ready,FUTEX_WAKE_PRIVATE,1);
    while(__atomic_load_n(&active.exec_ready,__ATOMIC_ACQUIRE))
        (void)raw(SYS_futex,(long)&active.exec_ready,FUTEX_WAIT_PRIVATE,1,0,0,0);
    return active.exec_result;
}

/* The supervisor retains the post-fork Bionic TLS and uses only raw syscalls
 * plus the read-only ELF validator (memcpy/memchr/memcmp/memset). It creates
 * no pthreads and uses no allocator or copied mutex before exec. */
static RAW_FN long snapshot_image(const char *path,int *output,struct sucrune_linux_plan *plan,
                                  struct sucrune_script_line *script) {
    begin_request(SUCRUNE_BROKER_OPEN_EXEC);
    size_t n=0;
    while(n<SUCRUNE_PATH_LIMIT && path[n]) n++;
    if(n==SUCRUNE_PATH_LIMIT) return -ENAMETOOLONG;
    active.request.size=(uint32_t)(n+1U);
    bytes_copy(active.request.data,path,n+1U);
    active.request.args[0]=AT_FDCWD;active.request.args[1]=O_RDONLY;
    long handle=transact();
    if(handle<0) return handle;
    if(handle<SUCRUNE_BROKER_HANDLE_BASE || handle>=SUCRUNE_BROKER_HANDLE_BASE+active.launch->fd_limit) return -EPROTO;
    int store=-1;
    long result;
    begin_request(80);active.request.args[0]=handle;result=transact();if(result<0) goto done;
    if(result!=0 || active.reply.size!=sizeof(struct sucrune_arm64_stat)) {result=-EPROTO;goto done;}
    struct sucrune_arm64_stat st;
    bytes_copy(&st,active.reply.data,sizeof(st));
    /* Same project-executable policy as snapshot_file() in the primary
     * loader. This guest ELF is read and mapped by Sucrune; Android only
     * execs the installed runner. Check the mode on the pinned file. */
    if(!sucrune_project_executable(&st,&active.launch->snapshot.owner)) {result=-EACCES;goto done;}
    if(st.size<1) {result=-ENOEXEC;goto done;}
    if(script!=NULL) {
        unsigned char header[SUCRUNE_SHEBANG_HEADER];
        size_t size = (uint64_t)st.size < sizeof(header) ? (size_t)st.size : sizeof(header);
        size_t used = 0;
        while(used<size) {
            begin_request(SUCRUNE_BROKER_PREAD64);
            active.request.args[0]=handle;active.request.args[1]=(int64_t)(size-used);active.request.args[2]=(int64_t)used;
            result=transact();
            if(result<=0 || (uint64_t)result>size-used || active.reply.size!=(uint32_t)result) {
                if(result>=0) result=-ENOEXEC;
                goto done;
            }
            bytes_copy(header+used,active.reply.data,(size_t)result);
            used+=(size_t)result;
        }
        result=sucrune_script_parse(header,size,script);
        if(result!=0) goto done;
    }
    if(st.size>(int64_t)SUCRUNE_LINUX_MAX_FILE) {result=-ENOEXEC;goto done;}
    result=R2(SYS_memfd_create,"sucrune-elf",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(result<0) goto done;
    store=(int)result;
    for(int64_t at=0;at<st.size;) {
        int64_t count=st.size-at;
        if(count>SUCRUNE_IO_LIMIT) count=SUCRUNE_IO_LIMIT;
        begin_request(SUCRUNE_BROKER_PREAD64);
        active.request.args[0]=handle;active.request.args[1]=count;active.request.args[2]=at;
        result=transact();
        if(result<=0 || result>count || active.reply.size!=(uint32_t)result) {if(result>=0) result=-ENOEXEC;goto done;}
        long written=R3(SYS_write,store,active.reply.data,result);
        if(written!=result) {result=written<0 ? written : -EIO;goto done;}
        at+=result;
    }
    result=R3(SYS_fcntl,store,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL);
    if(result<0) goto done;
    uintptr_t reserved=active.completion_writer>=0 ? (uintptr_t)child_context()+SUCRUNE_FORK_ARENA_BYTES : 0;
    void *view;
    if(reserved) {
        /* Changing protection cannot punch a hole in the shared parent
         * address space. Cancellation anywhere in the copy leaves the entire
         * range owned by the parent lease until actual exec/exit. */
        result=R3(SYS_mprotect,reserved,st.size,PROT_READ|PROT_WRITE);
        if(result<0) goto done;
        for(int64_t at=0;at<st.size;) {
            result=raw(SYS_pread64,store,(long)(reserved+(uintptr_t)at),(long)(st.size-at),(long)at,0,0);
            if(result==-EINTR) continue;
            if(result<=0) {
                if(result==0) result=-EIO;
                if(R3(SYS_mprotect,reserved,st.size,PROT_NONE)<0) die(125);
                (void)R3(SYS_madvise,reserved,st.size,MADV_DONTNEED);
                goto done;
            }
            at+=result;
        }
        view=(void *)reserved;
    } else {
        result=raw(SYS_mmap,0,(long)st.size,PROT_READ,MAP_PRIVATE,store,0);
        if(result<0) goto done;
        view=(void *)(uintptr_t)result;
    }
    int valid=sucrune_linux_validate(view,(size_t)st.size,active.launch->snapshot.space->page_size,plan)==SUCRUNE_ELF_OK;
    if(reserved) {
        if(R3(SYS_mprotect,reserved,st.size,PROT_NONE)<0) die(125);
        (void)R3(SYS_madvise,reserved,st.size,MADV_DONTNEED);
    } else (void)R2(SYS_munmap,view,st.size);
    result=valid ? R3(SYS_lseek,store,0,SEEK_SET) : -ENOEXEC;
done:
    begin_request(SUCRUNE_BROKER_PRIVATE_CLOSE);active.request.args[0]=handle;
    long closed=transact();if(result>=0 && closed!=0) result=closed;
    if(result==0) *output=store;
    else if(store>=0) (void)R1(SYS_close,store);
    return result;
}
static RAW_FN long snapshot_exec_program(struct sucrune_guest_exec *image, struct sucrune_linux_plan *plan) {
    const char *filename = (const char *)image->text;
    const char *path = filename;
    struct sucrune_script_chain chain = {0};
    image->script = 0;
    for (;;) {
        struct sucrune_script_line line = {0};
        long result = snapshot_image(path, &image->image_fd, plan, &line);
        if (result < 0) return result;
        if (result == 0) break;
        if (chain.count == SUCRUNE_SHEBANG_DEPTH) return -ELOOP;
        chain.lines[chain.count] = line;
        path = chain.lines[chain.count++].text;
    }
    if (!chain.count) return 0;
    const char *prefix[2U * SUCRUNE_SHEBANG_DEPTH + 1U];
    size_t count = sucrune_script_prefix(&chain, filename, prefix);
    if (count > SUCRUNE_GUEST_EXEC_ARGS - (image->argc - 1U)) return -E2BIG;
    size_t size = 0;
    for (size_t i=0; i<count; i++) size += strlen(prefix[i]) + 1U;
    size_t first = strlen(filename) + 1U;
    size_t rest = first + strlen((const char *)image->text + first) + 1U;
    size_t tail = image->text_size - rest;
    if (size > sizeof(image->text) - first - tail) return -E2BIG;
    memmove(image->text + first + size, image->text + rest, tail);
    size_t at = first;
    for (size_t i=0; i<count; i++) {
        size_t length = strlen(prefix[i]) + 1U;
        bytes_copy(image->text + at, prefix[i], length);
        at += length;
    }
    image->text_size = (uint32_t)(at + tail);
    image->argc += (uint32_t)(count - 1U);
    image->script = 1U;
    return 0;
}
static RAW_FN char *decimal(char text[16],int number) {
    char *end=text+15;*end='\0';
    unsigned int value=(unsigned int)number;
    do {*--end=(char)('0'+value%10U);value/=10U;} while(value!=0U);
    return end;
}
/* A pre-exec thread cannot allocate via libc or take the inherited process
 * group lock. Publish only a sealed, read-only snapshot of its own filtered
 * /proc record. A new open takes a fresh snapshot and has its own offset. */
static RAW_FN long open_proc_snapshot(int slot,uint64_t flags,int file) {
    if((flags&(O_ACCMODE|O_CREAT|O_TRUNC|O_EXCL))!=0U) return -EROFS;
    if((flags&O_DIRECTORY) && file!=SUCRUNE_PROC_NET_DIR) return -ENOTDIR;
    if(flags&~(uint64_t)(O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW|O_LARGEFILE|O_DIRECTORY)) return -EINVAL;
    if (file >= SUCRUNE_SYS_TCP && file <= SUCRUNE_SYS_UDP6) {
        begin_request(SUCRUNE_BROKER_PROC_NET_OPEN);
        active.request.args[0]=file;
        active.request.args[1]=(int64_t)(flags&O_CLOEXEC);
        active.request.args[2]=active.launch->snapshot.owner.guest_uid;
        long handle=transact();
        if (handle<0) return handle;
        if (active.reply.size || handle<SUCRUNE_BROKER_HANDLE_BASE ||
            handle>=SUCRUNE_BROKER_HANDLE_BASE+SUCRUNE_FILE_RESOURCES) return -EPROTO;
        record_new(slot,SUCRUNE_FD_BROKER,(int)(flags&O_NONBLOCK),0,-1);
        active.launch->handles[slot]=(int)handle;
        active.launch->fd_flags[slot]=(flags&O_CLOEXEC)!=0U;
        return slot;
    }
    char input[4096];
    unsigned char output[4096];
    int size;
    if(file==SUCRUNE_PROC_NET_DIR) {
        size_t length;
        const void *records=sucrune_proc_net_dirents(&length);
        if(length>sizeof(output)) return -EOVERFLOW;
        bytes_copy(output,records,length);
        size=(int)length;
    } else if(file) {
        begin_request(SUCRUNE_BROKER_PROC_CONTENTS);
        active.request.args[0]=file;
        long rc=transact();
        if(rc<0) return rc;
        if(rc || active.reply.size>sizeof(output)) return -EPROTO;
        size=(int)active.reply.size;
        bytes_copy(output,active.reply.data,(size_t)size);
    } else {
        long source=raw(SYS_openat,AT_FDCWD,(long)"/proc/self/stat",O_RDONLY|O_CLOEXEC|O_NOFOLLOW,0,0,0);
        if(source<0) return source;
        size_t used=0;
        long count;
        do {
            count=R3(SYS_read,source,input+used,sizeof(input)-used);
            if(count>0) used+=(size_t)count;
        } while((count>0 || count==-EINTR) && used<sizeof(input));
        (void)R1(SYS_close,source);
        if(count<0) return count;
        size=sucrune_proc_filter_stat(input,used,output);
        if(size<0) return size;
    }
    long store=R2(SYS_memfd_create,"sucrune-proc-stat",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(store<0) return store;
    long rc=R3(SYS_write,store,output,size);
    if(rc>=0 && rc!=size) rc=-EIO;
    if(rc==size) rc=R3(SYS_fcntl,store,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL);
    if(rc==0) {
        char path[40]="/proc/self/fd/",number[16];
        const char *digits=decimal(number,(int)store);
        bytes_copy(path+sizeof("/proc/self/fd/")-1U,digits,(size_t)(number+sizeof(number)-digits));
        rc=raw(SYS_openat,AT_FDCWD,(long)path,O_RDONLY|O_CLOEXEC|(long)(flags&O_NONBLOCK),0,0,0);
    }
    (void)R1(SYS_close,store);
    if(rc<0) return rc;
    record_new(slot,SUCRUNE_FD_LOCAL,(int)(flags&O_NONBLOCK),0,-1);
    active.proc_stat_resource[active.launch->metadata[slot].resource]=file ? (unsigned char)file : 1;
    active.launch->aliases[slot]=(int)rc;
    active.launch->fd_flags[slot]=(flags&O_CLOEXEC)!=0U;
    return slot;
}
static RAW_FN long prepare_exec_entries(void) {
    struct sucrune_guest_exec *image=&active.image;
    /* Check every alias before updating any broker-side CLOEXEC flags. */
    for(unsigned int i=0;i<active.launch->fd_limit;i++) {
        int resource=active.launch->metadata[i].resource;
        if(resource>=0 && active.launch->udp_resource[resource] && active.launch->fd_flags[i]==0U) {
            CHILD_REFUSAL("exec-keep-udp",(int)i);return -EOPNOTSUPP;
        }
    }
    for(unsigned int i=0;i<active.launch->fd_limit;i++) {
        image->entries[i]=(struct sucrune_exec_fd){.resource=-1,.broker_handle=-1,.local_alias=-1,.pty_number=-1};
        int alias=local_fd(i),handle=file_handle(i);
        if(alias<0 && handle<0) continue;
        int kept=active.launch->fd_flags[i]==0U;
        if(kept) {
            if(active.proc_stat_resource[active.launch->metadata[i].resource]) {
                CHILD_REFUSAL("exec-keep-proc-stat",(int)i);return -EOPNOTSUPP;
            }
            struct sucrune_exec_fd *entry=&image->entries[i];
            *entry=active.launch->metadata[i];entry->local_alias=alias;entry->broker_handle=handle;
            if(sucrune_pty_slave_handle(handle)) {
                begin_request(SUCRUNE_PTY_DESCRIBE);active.request.args[0]=handle;
                long number=transact();if(number<0) return number;if(number>INT_MAX) return -EPROTO;
                entry->pty_kind=SUCRUNE_PTY_SLAVE;entry->pty_number=(int32_t)number;
            }
            long flags;
            if(alias>=0) flags=R3(SYS_fcntl,alias,F_GETFL,0);
            else {begin_request(25);active.request.args[0]=handle;active.request.args[1]=F_GETFL;flags=transact();}
            if(flags<0) return flags;
            entry->status_flags=(int32_t)flags;
        }
        if(handle>=0 || active.launch->metadata[i].pty_kind==SUCRUNE_PTY_MASTER) {
            int first=1,any_kept=0,any_closed=0;
            for(unsigned int j=0;j<active.launch->fd_limit;j++) if(active.launch->metadata[j].resource==active.launch->metadata[i].resource) {
                if(j<i) first=0;
                if(active.launch->fd_flags[j]==0U) any_kept=1; else any_closed=1;
            }
            if(first) {
                if(handle>=0) {
                    begin_request(25);active.request.args[0]=handle;active.request.args[1]=F_SETFD;
                    active.request.args[2]=any_kept ? 0 : FD_CLOEXEC;
                    if (!sucrune_pty_slave_handle(handle)) active.request.args[3]=any_closed;
                } else {
                    begin_request(SUCRUNE_PTY_MASTER_EXEC);active.request.args[0]=active.launch->metadata[i].pty_number;
                    active.request.args[1]=any_kept ? 0 : FD_CLOEXEC;
                }
                long rc=transact();if(rc<0) return rc;
            }
        }
    }
    return 0;
}
static RAW_FN long replace_image(void) {
    struct sucrune_guest_exec *image=&active.image;
    struct sucrune_linux_plan program,interpreter;
    image->magic=SUCRUNE_GUEST_EXEC_MAGIC;image->version=SUCRUNE_GUEST_EXEC_VERSION;image->broker=active.launch->broker;
    image->scope=(struct sucrune_scope){active.launch->snapshot.scope_bus,active.scope_lease};
    image->image_fd=-1;image->interp_fd=-1;image->ignored_signals=0;
    image->signal_mask=active.launch->snapshot.signal_mask;image->linux_jit=active.launch->snapshot.linux_jit;
    image->exec_depth=active.launch->snapshot.exec_depth+1U;
    image->fd_limit=active.launch->fd_limit;
    image->build_profile=active.launch->snapshot.build_profile;
    for(unsigned int i=1;i<=64U;i++) if(active.launch->snapshot.signal_actions->actions[i].handler==1U)
        image->ignored_signals|=UINT64_C(1)<<(i-1U);
    int channels[2]={-1,-1};
    int keep_fds[SUCRUNE_LINUX_FD_LIMIT+6U],changed=0,count=0;
    long result=snapshot_exec_program(image,&program);
    if(result<0) goto done;
    if(program.interpreter[0]) {
        result=snapshot_image(program.interpreter,&image->interp_fd,&interpreter,NULL);
        if(result<0) goto done;
        if(interpreter.interpreter[0] || interpreter.load.fixed_address) {result=-ELIBBAD;goto done;}
    }
    result=prepare_exec_entries();if(result<0) goto done;
    result=raw(SYS_socketpair,AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,(long)channels,0,0);
    if(result<0) goto done;
    size_t prefix = SUCRUNE_GUEST_EXEC_PREFIX(image->fd_limit);
    struct iovec fragments[2] = {{image, prefix}, {image->text, image->text_size}};
    struct msghdr message = {.msg_iov=fragments, .msg_iovlen=2};
    size_t bytes = prefix + image->text_size;
    result=R3(SYS_sendmsg,channels[0],&message,MSG_NOSIGNAL|MSG_DONTWAIT);
    if(result!=(long)bytes) {if(result>=0) result=-EIO;goto done;}
    (void)R1(SYS_close,channels[0]);channels[0]=-1;
    keep_fds[count++]=channels[1];keep_fds[count++]=image->broker;keep_fds[count++]=image->image_fd;
    if(image->interp_fd>=0) keep_fds[count++]=image->interp_fd;
    if(image->scope.bus>=0) {keep_fds[count++]=image->scope.bus;keep_fds[count++]=image->scope.lease;}
    for(unsigned int i=0;i<active.launch->fd_limit;i++) if(image->entries[i].local_alias>=0)
        keep_fds[count++]=image->entries[i].local_alias;
    for(;changed<count;changed++) {
        result=R3(SYS_fcntl,keep_fds[changed],F_SETFD,0);
        if(result<0) goto done;
    }
    char chan[16],parent[16];
    const char *runner=active.launch->snapshot.runner;
    const char *arguments[]={runner,SUCRUNE_GUEST_EXEC_MODE,decimal(chan,channels[1]),decimal(parent,active.parent),NULL};
    const char *environment[]={NULL};
    result=R3(SYS_execve,runner,arguments,environment);
done:
    /* Never consume guest-visible CLOEXEC descriptors on failure. Marker
     * values in this broker session are private and recalculated on every
     * attempt. Only the fresh runner issues EXEC_COMMIT after host exec. */
    while(changed>0) (void)R3(SYS_fcntl,keep_fds[--changed],F_SETFD,FD_CLOEXEC);
    if(channels[0]>=0) (void)R1(SYS_close,channels[0]);
    if(channels[1]>=0) (void)R1(SYS_close,channels[1]);
    if(image->image_fd>=0) (void)R1(SYS_close,image->image_fd);
    if(image->interp_fd>=0) (void)R1(SYS_close,image->interp_fd);
    return result<0 ? result : -EIO;
}
static RAW_FN int signal_access(void *unused,uintptr_t addr,size_t size,int write) {
    (void)unused;
    return allowed(addr,size,write);
}
/* Host descriptors retain native pipe atomicity and socket message boundaries.
 * Copy the guest vector descriptors once before passing any spans to the kernel. */
static RAW_FN long child_vector_io(int op, int fd, int handle, const uint64_t *a) {
    if (fd < 0 && handle < 0) return -EBADF;
    if (a[2] > 1024U) return -EINVAL;
    size_t count = (size_t)a[2];
    struct iovec vectors[1024];
    if (count != 0U && !allowed((uintptr_t)a[1], count * sizeof(vectors[0]), 0)) return -EFAULT;
    bytes_copy(vectors, (const void *)(uintptr_t)a[1], count * sizeof(vectors[0]));
    size_t total = 0U;
    for (size_t i = 0U; i < count; i++) {
        size_t length = vectors[i].iov_len;
        if (length > (size_t)SSIZE_MAX - total) return -EINVAL;
        if (length != 0U && !allowed((uintptr_t)vectors[i].iov_base, length, op == 65)) return -EFAULT;
        total += length;
    }
    if (fd >= 0) return R3(op, fd, vectors, count);
    long transferred = 0;
    for (size_t i = 0U; i < count; i++) {
        size_t requested = vectors[i].iov_len;
        if (requested == 0U) continue;
        size_t size = requested > SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : requested;
        begin_request(op == 65 ? 63U : 64U);
        active.request.args[0] = handle; active.request.args[1] = (int64_t)size;
        if (op == 66) {
            active.request.size = (uint32_t)size;
            bytes_copy(active.request.data, vectors[i].iov_base, size);
        }
        long result = transact();
        if (result < 0) return transferred ? transferred : result;
        if ((size_t)result > size || active.reply.size != (op == 65 ? (uint32_t)result : 0U)) return -EPROTO;
        if (op == 65) bytes_copy(vectors[i].iov_base, active.reply.data, (size_t)result);
        transferred += result;
        if ((size_t)result < requested) break;
    }
    return transferred;
}
static RAW_FN long child_ppoll(const uint64_t *a) {
    if (a[1] > active.launch->fd_limit) return -EINVAL;
    if (a[3] != 0U) return a[4] == sizeof(uint64_t) ? -ENOTSUP : -EINVAL;
    size_t count = (size_t)a[1];
    struct pollfd *fds = active.poll_fds;
    struct pollfd *guest = (struct pollfd *)(uintptr_t)a[0];
    if (count != 0U && !allowed((uintptr_t)guest, count * sizeof(*guest), 1)) return -EFAULT;
    bytes_copy(fds, guest, count * sizeof(*guest));
    struct timespec timeout;
    if (a[2] != 0U) {
        if (!allowed((uintptr_t)a[2], sizeof(timeout), 1)) return -EFAULT;
        bytes_copy(&timeout, (const void *)(uintptr_t)a[2], sizeof(timeout));
        if (timeout.tv_sec < 0 || timeout.tv_nsec < 0 || timeout.tv_nsec >= 1000000000L) return -EINVAL;
    }
    /* This child has a private, single-threaded FD table. Local descriptors
     * remain valid until the call returns. Two temporary kernel descriptors
     * cover all workspace files, including O_PATH, without exporting data. */
    int files[2] = {-1,-1};
    long result = 0;
    for (size_t i = 0U; i < count; i++) {
        if (fds[i].fd < 0) continue;
        unsigned int slot = (unsigned int)fds[i].fd;
        int host = local_fd(slot), handle = file_handle(slot);
        if (host >= 0) fds[i].fd = host;
        else if (handle < 0) fds[i].fd = INT_MAX; /* Kernel reports POLLNVAL. */
        else if (handle >= (int)SUCRUNE_BROKER_HANDLE_BASE &&
                 handle < (int)(SUCRUNE_BROKER_HANDLE_BASE + active.launch->fd_limit)) {
            int path = (active.launch->metadata[slot].status_flags & O_PATH) != 0;
            if (files[path] < 0) {
                result = raw(SYS_openat, AT_FDCWD, (long)SUCRUNE_FILE_POLL_PATH,
                             O_RDONLY | O_CLOEXEC | (path ? O_PATH : 0), 0, 0, 0);
                if (result < 0) goto release;
                files[path] = (int)result;
            }
            fds[i].fd = files[path];
        } else { result = -ENOTSUP; goto release; }
    }
    result = raw(SYS_ppoll, (long)fds, (long)count, a[2] ? (long)&timeout : 0, 0, sizeof(uint64_t), 0);
    if (result >= 0) {
        for (size_t i = 0U; i < count; i++)
            bytes_copy(&guest[i].revents, &fds[i].revents, sizeof(fds[i].revents));
    }
    if (a[2] != 0U && (result >= 0 || result == -EINTR)) bytes_copy((void *)(uintptr_t)a[2], &timeout, sizeof(timeout));
release:
    for (size_t i = 0U; i < 2U; i++) if (files[i] >= 0) (void)R1(SYS_close, files[i]);
    return result;
}
static RAW_FN int child_ll_read(void *context, uintptr_t address, void *out, size_t size) {
    (void)context;
    if (!allowed(address, size, 0)) return -EFAULT;
    bytes_copy(out, (const void *)address, size);
    return 0;
}
static RAW_FN int child_ll_handle(void *context, int32_t fd, int64_t *handle) {
    (void)context;
    int project = file_handle((uint32_t)fd);
    if (project >= 0) { *handle = project; return 0; }
    int local = local_fd((uint32_t)fd);
    if (local < 0) return -EBADF;
    struct stat st;
    if (R2(SYS_fstat, local, &st) == 0 && sucrune_ll_is_null(&st)) {
        *handle = SUCRUNE_LL_NULL;
        return 0;
    }
    return -EBADFD;
}
static RAW_FN long child_ll_call(int op, const uint64_t *a) {
    begin_request((unsigned int)op);
    int error = sucrune_ll_request(&active.request, a, NULL, child_ll_read, child_ll_handle);
    if (error) return error;
    if (op != SUCRUNE_LL_CREATE || active.request.args[2] != 0) return transact();
    int slot = free_slot(0);
    if (slot < 0) return slot;
    long result = transact();
    if (result < 0) return result;
    if (active.reply.size || result < SUCRUNE_BROKER_HANDLE_BASE ||
        result >= SUCRUNE_BROKER_HANDLE_BASE + active.launch->fd_limit) return -EPROTO;
    record_new(slot, SUCRUNE_FD_BROKER, O_RDWR, 0, -1);
    active.launch->handles[slot] = (int)result;
    active.launch->fd_flags[slot] = SUCRUNE_FD_CLOEXEC;
    return slot;
}
static RAW_FN int child_ll_special_open(int id, uint64_t flags, int directory) {
    uint64_t access = sucrune_ll_special_access(flags, directory);
    if (!access) return 0;
    begin_request(SUCRUNE_BROKER_LL_SPECIAL);
    active.request.args[0] = id;
    active.request.args[1] = (int64_t)access;
    return (int)transact();
}
static RAW_FN long dispatch(int op,const uint64_t *a) {
    int fd=local_fd(a[0]),handle=file_handle(a[0]);
    int udp=fd>=0 && active.launch->udp_resource[active.launch->metadata[a[0]].resource];
    if(is_net_dir(a[0]) && (op==63 || op==65 || op==67 || op==69)) return -EISDIR;
    /* Raw read/write would skip datagram peer validation. Only the full
     * runner implements that path. Do not turn its kernel OFD blocking. */
    if (udp && (op==63 || op==64 || op==65 || op==66)) return -EOPNOTSUPP;
    switch(op) {
    case SUCRUNE_LL_PRCTL: case SUCRUNE_LL_CREATE: case SUCRUNE_LL_ADD: case SUCRUNE_LL_RESTRICT:
        return child_ll_call(op, a);
    case 17: {
        if(a[1]==0U || a[1]>(uint64_t)INT64_MAX) return -EINVAL;
        begin_request(17);active.request.args[0]=(int64_t)a[1];long result=transact();
        if(result<0) return result;
        if((uint64_t)result!=active.reply.size || (uint64_t)result>a[1]) return -EPROTO;
        if(!allowed((uintptr_t)a[0],(size_t)result,1)) return -EFAULT;
        bytes_copy((void *)(uintptr_t)a[0],active.reply.data,(size_t)result);return result;
    }
    case SUCRUNE_BROKER_SENDFILE: {
        int src = file_handle(a[1]);
        if ((handle < 0 && fd < 0) || (src < 0 && local_fd(a[1]) < 0)) return -EBADF;
        if (handle < 0 || src < 0 || sucrune_pty_slave_handle(handle) || sucrune_pty_slave_handle(src)) return -EINVAL;
        if (a[3] > INT64_MAX) return -EINVAL;
        uintptr_t pointer = (uintptr_t)a[2];
        int64_t offset = -1;
        if (pointer != 0U) {
            if (!allowed(pointer, sizeof(offset), 0) || !allowed(pointer, sizeof(offset), 1)) return -EFAULT;
            bytes_copy(&offset, (const void *)pointer, sizeof(offset));
            if (offset < 0) return -EINVAL;
        }
        begin_request(SUCRUNE_BROKER_SENDFILE);
        active.request.args[0] = handle; active.request.args[1] = src;
        active.request.args[2] = (int64_t)a[3]; active.request.args[3] = offset;
        long sent = transact();
        if (sent < 0) return sent;
        if (active.reply.size != 0U || (uint64_t)sent > a[3] ||
            (pointer != 0U && sent > INT64_MAX - offset)) return -EPROTO;
        if (pointer != 0U) { offset += sent; bytes_copy((void *)pointer, &offset, sizeof(offset)); }
        return sent;
    }
    case 23:return duplicate(a[0],0,0,0);
    case 24:if(a[2]!=0U && a[2]!=(uint64_t)O_CLOEXEC) return -EINVAL;
        return duplicate(a[0],a[1],a[2]!=0U ? 1U : 0U,1);
    case 25:
        if(fd<0 && handle<0) return -EBADF;
        if(a[1]==F_GETFD) return (long)active.launch->fd_flags[a[0]];
        if(a[1]==F_SETFD) {active.launch->fd_flags[a[0]]=(unsigned int)(a[2]&FD_CLOEXEC);return 0;}
        if (a[1]==F_GETLK || a[1]==F_SETLK || a[1]==F_SETLKW) {
            if (handle<0 || sucrune_pty_slave_handle(handle)) return -EOPNOTSUPP;
            size_t size=sizeof(struct sucrune_record_lock);
            if (!allowed((uintptr_t)a[2],size,0) || (a[1]==F_GETLK && !allowed((uintptr_t)a[2],size,1))) return -EFAULT;
            begin_request(SUCRUNE_BROKER_RECORD_LOCK);
            active.request.args[0]=handle;active.request.args[1]=a[1]==F_GETLK ? F_GETLK : F_SETLK;
            active.request.args[2]=active.pid;active.request.size=(uint32_t)size;
            bytes_copy(active.request.data,(const void *)(uintptr_t)a[2],size);
            long result;
            while ((result=transact())==-EAGAIN && a[1]==F_SETLKW) {
                if (active.reply.size!=size) return -EPROTO;
                bytes_copy(active.request.data,active.reply.data,size);
                struct timespec delay={.tv_nsec=10000000};
                if (R2(SYS_nanosleep,&delay,0)<0) return -EINTR;
            }
            if (result==0) {
                if (active.reply.size!=(a[1]==F_GETLK ? size : 0U)) return -EPROTO;
                if (a[1]==F_GETLK) bytes_copy((void *)(uintptr_t)a[2],active.reply.data,size);
                else active.may_have_record_locks=1;
            }
            return result;
        }
        if(handle>=0 && (a[1]==F_GETFL || a[1]==F_SETFL)) {begin_request(25);active.request.args[0]=handle;active.request.args[1]=(int64_t)a[1];active.request.args[2]=(int64_t)a[2];return transact();}
        if(udp && a[1]==F_GETFL) return active.launch->metadata[a[0]].status_flags;
        if(udp && a[1]==F_SETFL) return -EOPNOTSUPP;
        if(a[1]==F_GETFL) return R3(SYS_fcntl,fd,F_GETFL,0);
        if(a[1]==F_SETFL) {
            if((a[2]&~(uint64_t)(O_ACCMODE|O_NONBLOCK|O_APPEND|O_LARGEFILE))!=0U) return -EINVAL;
            if(active.launch->metadata[a[0]].network_token!=0U && (a[2]&O_NONBLOCK)==0U) return -EOPNOTSUPP;
            return R3(SYS_fcntl,fd,F_SETFL,a[2]);
        }
        if(a[1]==F_DUPFD || a[1]==F_DUPFD_CLOEXEC) return duplicate(a[0],a[2],a[1]==F_DUPFD_CLOEXEC ? 1U : 0U,0);
        return -ENOSYS;
    case 29:
        if(fd<0 && handle<0) return -EBADF;
        if(a[1]==FIOCLEX || a[1]==FIONCLEX) {
            active.launch->fd_flags[a[0]]=a[1]==FIOCLEX ? FD_CLOEXEC : 0U;return 0;
        }
        if(a[1]==FIONBIO) {
            int enabled=0;
            if(!allowed((uintptr_t)a[2],sizeof(enabled),0)) return -EFAULT;
            bytes_copy(&enabled,(const void *)(uintptr_t)a[2],sizeof(enabled));
            /* Keep fcntl's descriptor-kind policy, including network sockets. */
            uint64_t flags_args[3]={a[0],F_GETFL,0};
            long flags=dispatch(25,flags_args);if(flags<0) return flags;
            flags_args[1]=F_SETFL;
            flags_args[2]=(uint64_t)(enabled ? (flags|O_NONBLOCK) : (flags&~(long)O_NONBLOCK));
            return dispatch(25,flags_args);
        }
        if(sucrune_pty_slave_handle(handle)) return proxy_tty_ioctl(handle,a[1],a[2]);
        if(active.launch->metadata[a[0]].pty_kind==SUCRUNE_PTY_MASTER && a[1]==(uint64_t)_IO('T',0x41))
            return open_managed_tty(0,active.launch->metadata[a[0]].pty_number,a[2]);
        return sucrune_pty_child_ioctl(&pty_ops,(unsigned int)a[0],a[1],a[2]);
    case 36: {
        begin_request(36);
        long rc = guest_string((uintptr_t)a[0], (char *)active.request.data, SUCRUNE_PATH_LIMIT);
        if (rc < 0) return rc;
        active.request.size = (uint32_t)rc;
        rc = add_at_path(a[1], (uintptr_t)a[2], 0, 1);
        return rc < 0 ? rc : transact();
    }
    case 34:case 35:case 37:case 38:case 53: {
        begin_request((unsigned int)op);
        long rc=add_at_path(a[0],(uintptr_t)a[1],0,1);
        if(rc<0) return rc;
        if(op==34) {active.request.args[2]=(int64_t)(a[2]&0777U);active.request.args[3]=1;}
        if(op==35 || op==53) active.request.args[1]=(int64_t)a[2];
        if(op==37 || op==38) {
            rc=add_at_path(a[2],(uintptr_t)a[3],1,1);
            if(rc<0) return rc;
            if(op==37) active.request.args[2]=(int64_t)a[4];
        }
        return transact();
    }
    case 43: case 44: {
        if(!allowed((uintptr_t)a[1],sizeof(struct statfs),1)) return -EFAULT;
        begin_request((unsigned int)op);
        if(op==43) {
            long size=guest_string((uintptr_t)a[0],(char *)active.request.data,SUCRUNE_PATH_LIMIT);
            if(size<0) return size;
            const char *path=(const char *)active.request.data;
            const char *device=sucrune_device_path(active.request.data);
            if(sucrune_proc_path(path)) {
                if(!sucrune_proc_system_file(path) && !sucrune_proc_self_stat(path,active.pid) &&
                   !sucrune_proc_is_net_dir(path) && !sucrune_device_name(active.request.data,"/proc")) return -ENOENT;
                device="/proc";
            }
            if(device) return R2(SYS_statfs,device,a[1]);
            active.request.args[0]=AT_FDCWD; active.request.size=(uint32_t)size;
        } else {
            if(handle<0) {
                if(fd<0) return -EBADF;
                if(active.proc_stat_resource[active.launch->metadata[a[0]].resource]) return R2(SYS_statfs,"/proc",a[1]);
                return R2(SYS_fstatfs,fd,a[1]);
            }
            active.request.args[0]=handle;
        }
        long rc=transact();
        if(rc<0) return rc;
        if(rc || active.reply.size!=sizeof(struct statfs)) return -EPROTO;
        bytes_copy((void *)(uintptr_t)a[1],active.reply.data,sizeof(struct statfs)); return 0;
    }
    case 46:case 47:case 52:case 82:case 83:
        if(handle<0) return fd<0 ? -EBADF : -EINVAL;
        begin_request((unsigned int)op);
        active.request.args[0]=handle;
        if(op==46 || op==47 || op==52) active.request.args[1]=(int64_t)a[1];
        if(op==47) {active.request.args[2]=(int64_t)a[2];active.request.args[3]=(int64_t)a[3];}
        return transact();
    case 48:case 439:case 78:case 79: {
        begin_request((unsigned int)op);
        uint64_t flags=op==48 ? 0U : a[3];
        if(op==79 && (flags&AT_EMPTY_PATH)!=0U) {
            if((flags&~(uint64_t)(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT))!=0U) return -EINVAL;
            if(!allowed((uintptr_t)a[1],1U,0)) return -EFAULT;
            if(*(const volatile unsigned char *)(uintptr_t)a[1]==0U && (int32_t)a[0]!=AT_FDCWD) {
                uint64_t stat_args[]={a[0],a[2]};
                return dispatch(80,stat_args);
            }
            flags&=~(uint64_t)AT_EMPTY_PATH;
        }
        long rc=add_at_path(a[0],(uintptr_t)a[1],0,0);
        if(rc<0) return rc;
        int system_file=sucrune_proc_system_file((const char *)active.request.data);
        int net_dir=sucrune_proc_is_net_dir((const char *)active.request.data);
        int proc_stat=sucrune_proc_self_stat((const char *)active.request.data,active.pid);
        if(op==48 || op==439) {
            if((a[2]&~UINT64_C(7))!=0U || (flags&~(uint64_t)(AT_EACCESS|AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH))!=0U)
                return -EINVAL;
            const char *device = sucrune_device_path(active.request.data);
            if (device != NULL) {
                if (sucrune_device_readonly(device) && (a[2] & W_OK)) return -EACCES;
                return raw(SYS_faccessat,AT_FDCWD,(long)device,(long)a[2],0,0,0);
            }
            if(net_dir) return (a[2]&W_OK) ? -EACCES : 0;
            if(proc_stat || system_file) return (a[2]&(W_OK|X_OK))!=0U ? -EACCES : 0;
            active.request.args[1]=(int64_t)a[2];
            active.request.args[2]=(int64_t)flags;
            return transact();
        }
        size_t count=op==79 ? sizeof(struct sucrune_arm64_stat) :
            (a[3]>SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)a[3]);
        if(count==0U) return -EINVAL;
        if(!allowed((uintptr_t)a[2],count,1)) return -EFAULT;
        if(proc_stat || system_file || net_dir) {
            if(op==78) return -EINVAL;
            if((flags&~(uint64_t)(AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT))!=0U) return -EINVAL;
            if(system_file || net_dir) {
                if(net_dir) system_file=SUCRUNE_PROC_NET_DIR;
                struct sucrune_arm64_stat st;
                sucrune_proc_system_stat(system_file,&st); bytes_copy((void *)(uintptr_t)a[2],&st,sizeof(st)); return 0;
            }
            return raw(SYS_newfstatat,AT_FDCWD,(long)"/proc/self/stat",(long)a[2],(long)flags,0,0);
        }
        const char *device = sucrune_device_path(active.request.data);
        if(device != NULL) {
            if(op==78) return -EINVAL;
            if((flags&~(uint64_t)(AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT))!=0U) return -EINVAL;
            return raw(SYS_newfstatat,AT_FDCWD,(long)device,(long)a[2],(long)flags,0,0);
        }
        active.request.args[1]=op==79 ? (int64_t)(flags&~(uint64_t)AT_NO_AUTOMOUNT) : (int64_t)count;
        long result=transact();
        if(result<0) return result;
        if(op==79) return result==0 ? copy_project_stat((uintptr_t)a[2]) : -EPROTO;
        if((uint64_t)result>count || active.reply.size!=(uint32_t)result) return -EPROTO;
        bytes_copy((void *)(uintptr_t)a[2],active.reply.data,active.reply.size);
        return result;
    }
    case 50:
        if (handle < 0) return fd < 0 ? -EBADF : -ENOTDIR;
        begin_request(50);active.request.args[0]=handle;return transact();
    case 49:case 56: {
        int target=op==56 ? free_slot(0) : 0;if(target<0) return target;
        begin_request((unsigned int)op);
        long size=guest_string((uintptr_t)a[op==56 ? 1 : 0],(char *)active.request.data,SUCRUNE_PATH_LIMIT);
        if(op==56) size=net_dir_path(a[0],(char *)active.request.data,size);
        if(size<0) return size;active.request.size=(uint32_t)size;
        if(sucrune_proc_path((const char *)active.request.data)) {
            int system_file=sucrune_proc_system_file((const char *)active.request.data);
            int dir=sucrune_proc_is_net_dir((const char *)active.request.data);
            if(dir) system_file=SUCRUNE_PROC_NET_DIR;
            if(op==56 && (system_file || sucrune_proc_self_stat((const char *)active.request.data,active.pid))) {
                int rc = child_ll_special_open(SUCRUNE_LL_OTHER_SPECIAL, a[2], dir);
                if (rc < 0) return rc;
                return open_proc_snapshot(target,a[2],system_file);
            }
            return -ENOENT;
        }
        if(op==56) {
            const char *device = sucrune_device_path(active.request.data);
            if (device != NULL) {
                int id = sucrune_device_name((const unsigned char *)device, "/dev/null") ?
                    SUCRUNE_LL_NULL : SUCRUNE_LL_OTHER_SPECIAL;
                int access = child_ll_special_open(id, a[2], 0);
                if (access < 0) return access;
                int native_flags = sucrune_device_open_flags(device, a[2]);
                if (native_flags < 0) return native_flags;
                long alias = raw(SYS_openat, AT_FDCWD, (long)device, native_flags, 0, 0, 0);
                if (alias < 0) return alias;
                record_new(target, SUCRUNE_FD_LOCAL, (int)a[2] & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_PATH), 0, -1);
                active.launch->aliases[target] = (int)alias;
                active.launch->fd_flags[target] = (a[2] & O_CLOEXEC) != 0U;
                return target;
            }
            if(sucrune_pty_path((const char *)active.request.data)) {
                int access = child_ll_special_open(SUCRUNE_LL_OTHER_SPECIAL, a[2], 0);
                if (access < 0) return access;
                return open_tty_path((const char *)active.request.data,a[2]);
            }
            if (active.request.data[0]=='/' || (int32_t)a[0]==AT_FDCWD) active.request.args[0]=AT_FDCWD;
            else {
                if (handle<0) return fd<0 ? -EBADF : -ENOTDIR;
                active.request.args[0]=handle;
            }
            active.request.args[1]=(int64_t)(a[2]&~(uint64_t)O_CLOEXEC);
            if ((a[2]&O_CREAT)!=0U) {active.request.args[2]=(int64_t)(a[3]&0777U);active.request.args[3]=1;}
        }
        long result=transact();if(result<0 || op==49) return result;
        if(result<(long)SUCRUNE_BROKER_HANDLE_BASE || result>=(long)(SUCRUNE_BROKER_HANDLE_BASE+active.launch->fd_limit)) return -EPROTO;
        record_new(target,SUCRUNE_FD_BROKER,(int)(a[2]&(O_NONBLOCK|O_APPEND|O_ACCMODE|O_PATH)),0,-1);
        active.launch->handles[target]=(int)result;active.launch->fd_flags[target]=(a[2]&O_CLOEXEC)!=0U ? 1U : 0U;return target;
    }
    case 57:return a[0]<active.launch->fd_limit ? close_guest((unsigned int)a[0]) : -EBADF;
    case 59: {
        if((a[1]&~(uint64_t)(O_NONBLOCK|O_CLOEXEC))!=0U) return -EINVAL;
        if(!allowed((uintptr_t)a[0],8U,1)) return -EFAULT;
        int first=free_slot(0);if(first<0) return first;
        int second=free_slot((unsigned int)first+1U);if(second<0) return second;
        int pair[2];long result=R2(SYS_pipe2,pair,a[1]|O_CLOEXEC);if(result<0) return result;
        record_new(first,SUCRUNE_FD_LOCAL,O_RDONLY|(int)(a[1]&O_NONBLOCK),0,-1);
        record_new(second,SUCRUNE_FD_LOCAL,O_WRONLY|(int)(a[1]&O_NONBLOCK),0,-1);
        active.launch->aliases[first]=pair[0];active.launch->aliases[second]=pair[1];
        active.launch->fd_flags[first]=active.launch->fd_flags[second]=(a[1]&O_CLOEXEC)!=0U ? 1U : 0U;
        int32_t guest[2]={first,second};bytes_copy((void *)(uintptr_t)a[0],guest,sizeof(guest));return 0;
    }
    case SUCRUNE_BROKER_UMASK:
        begin_request(SUCRUNE_BROKER_UMASK);
        active.request.args[0]=(int64_t)(a[0]&0777U);
        return transact();
    case SUCRUNE_BROKER_UTIMENSAT: {
        struct timespec times[2];
        if (a[2]) {
            if (!allowed((uintptr_t)a[2],sizeof(times),0)) return -EFAULT;
            bytes_copy(times,(const void *)(uintptr_t)a[2],sizeof(times));
            if (times[0].tv_nsec==UTIME_OMIT && times[1].tv_nsec==UTIME_OMIT) return 0;
        }
        if ((a[3]&~(uint64_t)(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW))!=0U) return -EINVAL;
        begin_request(SUCRUNE_BROKER_UTIMENSAT);
        active.request.args[1]=(int64_t)a[3];
        if (a[1]) {
            long error=add_at_path(a[0],(uintptr_t)a[1],0,1);
            if (error<0) return error;
        } else {
            if ((int32_t)a[0]==AT_FDCWD) return -EFAULT;
            if (a[3]) return -EINVAL;
            if (handle<0) return fd<0 ? -EBADF : -ENOTSUP;
            active.request.args[0]=handle;
            active.request.args[1]=AT_EMPTY_PATH;
            active.request.data[0]=0;
            active.request.size=1;
        }
        if (a[2]) {
            active.request.args[2]=1;
            bytes_copy(active.request.data+active.request.size,times,sizeof(times));
            active.request.size+=(uint32_t)sizeof(times);
        }
        return transact();
    }
    case 32: {
        if(handle<0) return fd<0 ? -EBADF : -EOPNOTSUPP;
        int blocking = a[1] == LOCK_SH || a[1] == LOCK_EX;
        begin_request(SUCRUNE_BROKER_FLOCK);
        active.request.args[0] = handle;
        active.request.args[1] = (int64_t)(blocking ? a[1] | LOCK_NB : a[1]);
        long result;
        const struct timespec delay = {.tv_nsec = 10000000};
        while ((result = transact()) == -EWOULDBLOCK && blocking) {
            long slept = R2(SYS_nanosleep, &delay, 0);
            if (slept < 0) return slept;
        }
        return result;
    }
    case 62:
        if(is_net_dir(a[0]) && (a[1]!=0 || a[2]!=SEEK_SET)) return -EINVAL;
        if(handle<0) return fd<0 ? -EBADF : R3(SYS_lseek,fd,a[1],a[2]);
        begin_request((unsigned int)op);active.request.args[0]=handle;active.request.args[1]=(int64_t)a[1];active.request.args[2]=(int64_t)a[2];return transact();
    case 61: {
        size_t count=a[2]>SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)a[2];
        if(is_net_dir(a[0])) {
            count-=count%SUCRUNE_PROC_NET_RECLEN;
            if(!count) return -EINVAL;
            if(!allowed((uintptr_t)a[1],count,1)) return -EFAULT;
            return R3(SYS_read,fd,a[1],count);
        }
        if(handle<0) return fd<0 ? -EBADF : -ENOTDIR;
        if(count!=0 && !allowed((uintptr_t)a[1],count,1)) return -EFAULT;
        begin_request(61);active.request.args[0]=handle;active.request.args[1]=(int64_t)count;
        long result=transact();
        if(result<0) return result;
        if((uint64_t)result>count || active.reply.size!=(uint32_t)result) return -EPROTO;
        bytes_copy((void *)(uintptr_t)a[1],active.reply.data,active.reply.size);
        return result;
    }
    case 63:case 64:
        if(fd<0 && handle<0) return -EBADF;
        if(a[2]>(uint64_t)SSIZE_MAX || (a[2]!=0U && !allowed((uintptr_t)a[1],(size_t)a[2],op==63))) return -EFAULT;
        if(handle>=0) {
            size_t count=a[2]>SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)a[2];
            begin_request((unsigned int)op);active.request.args[0]=handle;active.request.args[1]=(int64_t)count;
            if(op==64) {active.request.size=(uint32_t)count;bytes_copy(active.request.data,(const void *)(uintptr_t)a[1],count);}
            long result=transact();if(result<0) return result;
            if((unsigned long)result>count || active.reply.size!=(op==63 ? (uint32_t)result : 0U)) return -EPROTO;
            if(op==63) bytes_copy((void *)(uintptr_t)a[1],active.reply.data,(size_t)result);
            return result;
        }
        return R3(op,fd,a[1],a[2]);
    case 65: case 66: return child_vector_io(op, fd, handle, a);
    case 73: return child_ppoll(a);
    case 80: {
        if(!allowed((uintptr_t)a[1],sizeof(struct sucrune_arm64_stat),1)) return -EFAULT;
        if(fd>=0 && active.proc_stat_resource[active.launch->metadata[a[0]].resource]) {
            int file=active.proc_stat_resource[active.launch->metadata[a[0]].resource];
            if(file==1) return raw(SYS_newfstatat,AT_FDCWD,(long)"/proc/self/stat",(long)a[1],0,0,0);
            struct sucrune_arm64_stat st;
            sucrune_proc_system_stat(file,&st); bytes_copy((void *)(uintptr_t)a[1],&st,sizeof(st)); return 0;
        }
        if(handle<0) return fd<0 ? -EBADF : R2(SYS_fstat,fd,a[1]);
        begin_request(80);active.request.args[0]=handle;
        long result=transact();
        if(result<0) return result;
        return result==0 ? copy_project_stat((uintptr_t)a[1]) : -EPROTO;
    }
    case 93:case 94:die((int)(a[0]&255U));
    case 96: {
        if(a[0]!=0U && ((a[0]&3U)!=0U || !allowed((uintptr_t)a[0],4U,1))) return -EFAULT;
        /* The supervisor is the guest process leader that performs exec.
         * Register the address on that kernel task, so its mm_release drives
         * exit/exec clearing even when the separate trap worker is killed. */
        active.requested_clear_tid=(uintptr_t)a[0];
        __atomic_store_n(&active.exec_ready,3,__ATOMIC_RELEASE);
        (void)R3(SYS_futex,&active.exec_ready,FUTEX_WAKE_PRIVATE,1);
        while(__atomic_load_n(&active.exec_ready,__ATOMIC_ACQUIRE))
            (void)raw(SYS_futex,(long)&active.exec_ready,FUTEX_WAIT_PRIVATE,3,0,0,0);
        return active.exec_result;
    }
    case 101:case 115:return child_sleep(op,a);
    case 153:
        if (a[0] && !allowed((uintptr_t)a[0], sizeof(struct tms), 1)) return -EFAULT;
        return R1(SYS_times, a[0]);
    case 165:
        if (!allowed((uintptr_t)a[1], sizeof(struct rusage), 1)) return -EFAULT;
        return R2(SYS_getrusage, (int)a[0], a[1]);
    case 169:
        if ((a[0] && !allowed((uintptr_t)a[0], sizeof(struct timeval), 1)) ||
            (a[1] && !allowed((uintptr_t)a[1], sizeof(struct timezone), 1))) return -EFAULT;
        return R2(SYS_gettimeofday, a[0], a[1]);
    case 113:case 114:
        if(a[0]!=CLOCK_REALTIME && a[0]!=CLOCK_MONOTONIC && a[0]!=CLOCK_PROCESS_CPUTIME_ID &&
           a[0]!=CLOCK_THREAD_CPUTIME_ID && a[0]!=CLOCK_MONOTONIC_RAW && a[0]!=CLOCK_REALTIME_COARSE &&
           a[0]!=CLOCK_MONOTONIC_COARSE && a[0]!=CLOCK_BOOTTIME) return -EINVAL;
        if((a[1]!=0 || op==113) && !allowed((uintptr_t)a[1],sizeof(struct timespec),1)) return -EFAULT;
        return R2(op,a[0],a[1]);
    case 179:
        if(!allowed((uintptr_t)a[0],sizeof(struct sysinfo),1)) return -EFAULT;
        return R1(SYS_sysinfo,a[0]);
    case 123: {
        if((int32_t)a[0]!=0 && (int32_t)a[0]!=active.tid && (int32_t)a[0]!=active.pid) return -ESRCH;
        cpu_set_t mask;
        size_t count=a[1]>sizeof(mask) ? sizeof(mask) : (size_t)a[1];
        long rc=R3(SYS_sched_getaffinity,a[0],count,&mask);
        if(rc<0) return rc;
        if(!allowed((uintptr_t)a[2],(size_t)rc,1)) return -EFAULT;
        bytes_copy((void *)(uintptr_t)a[2],&mask,(size_t)rc); return rc;
    }
    case 160: {
        struct utsname name;
        if(!allowed((uintptr_t)a[0],sizeof(name),1)) return -EFAULT;
        long rc=R1(SYS_uname,&name);
        if(rc<0) return rc;
        for(size_t i=0;i<sizeof(name.nodename);i++) name.nodename[i]='\0';
        for(size_t i=0;i<sizeof(name.domainname);i++) name.domainname[i]='\0';
        bytes_copy(name.nodename,"sucrune",sizeof("sucrune"));
        bytes_copy(name.domainname,"(none)",sizeof("(none)"));
        bytes_copy((void *)(uintptr_t)a[0],&name,sizeof(name));
        return 0;
    }
    case 278: {
        size_t count=a[1]>SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)a[1];
        if((a[2]&~UINT64_C(3))!=0) return -EINVAL;
        if(count && !allowed((uintptr_t)a[0],count,1)) return -EFAULT;
        return R3(SYS_getrandom,a[0],count,a[2]);
    }
    case 129: {
        int32_t pid=(int32_t)a[0], signo=(int32_t)a[1];
        if(pid<=0 && !(active.launch->snapshot.scope_bus>=0 && pid < -1 && pid != INT32_MIN)) return -EOPNOTSUPP;
        if(pid!=active.pid) return active.launch->snapshot.scope_bus>=0 ?
            sucrune_scope_signal(active.launch->snapshot.scope_bus,pid,signo) : -ESRCH;
        if(signo!=0 && (signo!=SIGSTOP || active.scope_lease>=0)) return -EOPNOTSUPP;
        return R2(SYS_kill,active.pid,signo);
    }
    case 168:
        if ((a[0] && !allowed((uintptr_t)a[0], sizeof(unsigned int), 1)) ||
            (a[1] && !allowed((uintptr_t)a[1], sizeof(unsigned int), 1))) return -EFAULT;
        return R3(SYS_getcpu, a[0], a[1], 0);
    case 172:case 178:return active.pid;
    case 173:return R0(SYS_getppid);
    case 154: {
        int32_t pid=(int32_t)a[0],group=(int32_t)a[1];
        if(group<0) return -EINVAL;
        if(pid!=0 && pid!=active.pid) return -ESRCH;
        if(group!=0 && group!=active.pid && !own_group(NULL,group)) return join_sibling_group(group);
        return R2(SYS_setpgid,0,group);
    }
    case 155:case 156:return a[0]==0 || a[0]==(uint64_t)active.pid ? R1(op,0) : -ESRCH;
    case 157:return sucrune_pty_child_setsid(&pty_ops);
    case 221:return request_exec(a);
    case 260:return nested_wait(a);
    case 158: {
        if (a[0] > INT32_MAX) return -EINVAL;
        long count = R2(SYS_getgroups,0,0);
        if (count <= 0 || a[0] == 0U) return count;
        if (a[0] < (uint64_t)count) return -EINVAL;
        if (!allowed((uintptr_t)a[1],(size_t)count * sizeof(gid_t),1)) return -EFAULT;
        return R2(SYS_getgroups,count,a[1]);
    }
    case 163: { /* getrlimit fallback on AArch64. */
        uint64_t query[4]={0,a[0],0,a[1]};return dispatch(261,query);
    }
    case 261: { /* JDK's pre-exec closeDescriptors() falls back to _SC_OPEN_MAX. */
        if(a[0]!=0U || a[2]!=0U) return -EPERM;
        if(a[1]!=RLIMIT_NOFILE) return -ENOSYS;
        if(a[3]!=0U) {
            if(!allowed((uintptr_t)a[3],sizeof(struct rlimit),1)) return -EFAULT;
            struct rlimit limit={active.launch->fd_limit,active.launch->fd_limit};
            bytes_copy((void *)(uintptr_t)a[3],&limit,sizeof(limit));
        }
        return 0;
    }
    case 174:case 175:case 176:case 177:return R0(op);
    case 134: {
        if(a[0]==0U || a[0]>64U || a[3]!=8U) return -EINVAL;
        if(a[1] && (a[0]==SIGKILL || a[0]==SIGSTOP)) return -EINVAL;
        struct sucrune_signal_action new_action;
        if(a[1]) {if(!allowed((uintptr_t)a[1],sizeof(new_action),0)) return -EFAULT;bytes_copy(&new_action,(const void *)(uintptr_t)a[1],sizeof(new_action));if(new_action.handler>1U) return -ENOTSUP;}
        struct sucrune_signal_process *actions=(struct sucrune_signal_process *)active.launch->snapshot.signal_actions;
        if(a[2]) {if(!allowed((uintptr_t)a[2],sizeof(new_action),1)) return -EFAULT;bytes_copy((void *)(uintptr_t)a[2],&actions->actions[a[0]],sizeof(new_action));}
        if(a[1]) {
            if(active.scope_lease>=0 && (a[0]==SIGHUP || a[0]==SIGINT || a[0]==SIGTERM)) {
                /* This raw dispatcher supports the default and ignore actions. */
                uint64_t action[4]={new_action.handler,0,0,0};
                long rc=raw(SYS_rt_sigaction,(long)a[0],(long)action,0,8,0,0);
                if(rc<0) return rc;
            }
            bytes_copy(&actions->actions[a[0]],&new_action,sizeof(new_action));
        }
        return 0;
    }
    case 135: {
        if(a[3]!=8U || (a[1] && a[0]>2U)) return -EINVAL;
        uint64_t set=0,old=active.launch->snapshot.signal_mask;
        if(a[1]) {if(!allowed((uintptr_t)a[1],8U,0)) return -EFAULT;bytes_copy(&set,(const void *)(uintptr_t)a[1],8U);}
        if(a[2]) {if(!allowed((uintptr_t)a[2],8U,1)) return -EFAULT;bytes_copy((void *)(uintptr_t)a[2],&old,8U);}
        if(a[1]) active.launch->snapshot.signal_mask=(a[0]==0 ? old|set : a[0]==1 ? old&~set : set)&~((UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
        return 0;
    }
    case 436:
        if(a[0]>a[1] || (a[2]!=0U && a[2]!=4U)) return -EINVAL;
        for(uint64_t i=a[0];i<active.launch->fd_limit && i<=a[1];i++) if(local_fd(i)>=0 || file_handle(i)>=0) {
            if(a[2]==4U) active.launch->fd_flags[i]=1U;else (void)close_guest((unsigned int)i);
        }
        return 0;
    default:return -ENOSYS;
    }
}
RAW_FN __attribute__((visibility("hidden"))) void sucrune_fork_handle_signal(int number,siginfo_t *info,void *context,uintptr_t guest_tls) {
    unsigned char marker;
    uintptr_t where=(uintptr_t)&marker;
    if(info==NULL || context==NULL || where<active.alt_low || where-active.alt_low>=ALT_BYTES || R0(SYS_gettid)!=active.tid) die(159);
    ucontext_t *uc=context;
    if(number==SIGUSR2 && active.bootstrap && info->si_code==SI_TKILL && info->si_pid==active.pid) {
        int result=fork_cpu(uc,&active.launch->snapshot.cpu,0);
        if(result!=0) fail(result);
        active.bootstrap=0;receipt(0);return;
    }
    if(number!=SIGSYS || info->si_code!=1 || info->si_errno!=(int)FORK_TRAP_TAG || info->si_arch!=AUDIT_ARCH_AARCH64 ||
        uc->uc_mcontext.pc<4U || !executable((uintptr_t)uc->uc_mcontext.pc-4U)) die(159);
    active.syscalls++;
    if(info->si_syscall==220) {
        uc->uc_mcontext.regs[0]=(uint64_t)nested_clone(uc,guest_tls);
    } else if(info->si_syscall==132) {
        const struct sucrune_signal_memory memory={.access=signal_access};
        uc->uc_mcontext.regs[0]=(uint64_t)(int64_t)sucrune_signals_altstack(&active.launch->snapshot.signal_stack,
            &memory,(uintptr_t)uc->uc_mcontext.sp,(uintptr_t)uc->uc_mcontext.regs[0],(uintptr_t)uc->uc_mcontext.regs[1]);
    } else uc->uc_mcontext.regs[0]=(uint64_t)dispatch(info->si_syscall,(const uint64_t *)uc->uc_mcontext.regs);
    long result=(long)uc->uc_mcontext.regs[0];
    if(active.launch->snapshot.trace_syscalls && active.syscalls<=4096U && result<0 && result>=-4095) {
        char call[16],error[16];
        char *n=decimal(call,info->si_syscall),*e=decimal(error,(int)-result);
        struct iovec line[]={{"[child syscall ",sizeof("[child syscall ")-1U},{n,(size_t)(call+15-n)},
            {" errno ",sizeof(" errno ")-1U},{e,(size_t)(error+15-e)},{"]\n",2U}};
        (void)R3(SYS_writev,2,line,sizeof(line)/sizeof(line[0]));
    }
}
static RAW_FN size_t range_filter(struct sock_filter *code,uintptr_t low,uintptr_t high) {
    const unsigned int ip=(unsigned int)offsetof(struct seccomp_data,instruction_pointer);
    struct sock_filter items[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,ip+4U),
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,(uint32_t)(low>>32U),0,9),BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K,(uint32_t)(high>>32U),8,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(low>>32U),0,2),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,ip),
        BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K,(uint32_t)low,0,5),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,ip+4U),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(high>>32U),0,2),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,ip),
        BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K,(uint32_t)high,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRAP|FORK_TRAP_TAG)};
    for(size_t i=0;i<sizeof(items)/sizeof(items[0]);i++) code[i]=items[i];
    return sizeof(items)/sizeof(items[0]);
}
static RAW_FN void worker(void *unused) {
    (void)unused;
    active.tid=(pid_t)R0(SYS_gettid);
    struct sucrune_process_snapshot *s=&active.launch->snapshot;
    stack_t stack={.ss_sp=(void *)active.alt_low,.ss_flags=0,.ss_size=ALT_BYTES};
    long result=R2(SYS_sigaltstack,&stack,0);
    if(result<0) fail(result);
    uint64_t mask=~(UINT64_C(1)<<(SIGUSR2-1)) & ~(UINT64_C(1)<<(SIGSYS-1));
    result=raw(SYS_rt_sigprocmask,SIG_SETMASK,(long)&mask,0,8,0,0);
    if(result<0) fail(result);
    struct sock_filter code[32];
    code[0]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,(unsigned int)offsetof(struct seccomp_data,arch));
    code[1]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0);
    code[2]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS);
    size_t used=3U;
    used+=range_filter(code+used,s->space->base,s->space->base+s->space->size);
    if(s->fixed_space->base) used+=range_filter(code+used,s->fixed_space->base,s->fixed_space->base+s->fixed_space->size);
    code[used++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
    struct sock_fprog filter={(unsigned short)used,code};
    result=raw(SYS_prctl,PR_SET_NO_NEW_PRIVS,1,0,0,0,0);
    if(result==0) result=raw(SYS_prctl,PR_SET_SECCOMP,SECCOMP_MODE_FILTER,(long)&filter,0,0,0);
    if(result<0) fail(result);
    if((s->flags&CLONE_CHILD_SETTID)!=0U) *(volatile int32_t *)s->child_tid=active.pid;
    active.bootstrap=1;
    sucrune_fork_resume(s->tls,s->cpu.regs[18],active.pid,active.tid);
}
struct kernel_action {void (*entry)(int,siginfo_t *,void *);uint64_t flags;void (*restorer)(void);uint64_t mask;};
/* A shared-VM child can be killed at any instruction. Keeping its trusted
 * stacks and temporary file mappings in a known lease makes reclamation
 * independent of exit handlers in the child. */
static RAW_FN long prepare_arena(const struct sucrune_fork_launch *launch,int channel,pid_t expected,int done_fd) {
    size_t page=launch->snapshot.space->page_size;
    if(page!=4096U && page!=16384U && page!=65536U) return -EINVAL;
    const size_t alignment=SUCRUNE_FORK_ARENA_BYTES;
    size_t length=alignment+(done_fd>=0 ? SUCRUNE_LINUX_MAX_FILE : 0U);
    long result=raw(SYS_mmap,0,(long)(length+alignment),PROT_NONE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
    if(result<0) return result;
    uintptr_t start=(uintptr_t)result,base=(start+alignment-1U)&~(uintptr_t)(alignment-1U);
    size_t prefix=base-start,suffix=alignment-prefix;
    if(prefix) (void)R2(SYS_munmap,start,prefix);
    if(suffix) (void)R2(SYS_munmap,base+length,suffix);
    result=R3(SYS_mprotect,base,alignment,PROT_READ|PROT_WRITE);
    const uintptr_t guards[]={0x110000,0x170000,SUCRUNE_FORK_WORKER_TOP,SUCRUNE_FORK_ALT_BASE+ALT_BYTES};
    for(size_t i=0;result==0 && i<sizeof(guards)/sizeof(guards[0]);i++)
        result=R3(SYS_mprotect,base+guards[i],page,PROT_NONE);
    if(result<0) {(void)R2(SYS_munmap,base,length);return result;}
    struct child_state *child=(void *)base;
    child->supervisor_tls=base+0xb8000;child->supervisor_scs=base+0xc0000;
    child->gate_tls=base+0xd8000;child->gate_scs=base+0xe0000;
    child->alt_low=base+SUCRUNE_FORK_ALT_BASE;
    child->scope_lease=-1;
    child->receipt=channel;child->parent=expected;child->completion_writer=done_fd;
    child->launch=&child->owned;
    bytes_copy(&child->owned,launch,sizeof(*launch));
    bytes_copy(child->proc_stat_resource,launch->proc_stat_resource,sizeof(child->proc_stat_resource));
    bytes_copy(&child->dispositions,launch->snapshot.signal_actions,sizeof(child->dispositions));
    child->owned.snapshot.signal_actions=&child->dispositions;
    if(done_fd>=0) {
        /* Host page protections remain authoritative. Preserve the logical
         * clone-time ranges used by this bounded pre-exec dispatcher without
         * racing concurrent guest threads' VMA table transactions. */
        bytes_copy(&child->initial_space,launch->snapshot.space,sizeof(child->initial_space));
        bytes_copy(&child->initial_fixed,launch->snapshot.fixed_space,sizeof(child->initial_fixed));
        child->owned.snapshot.space=&child->initial_space;
        child->owned.snapshot.fixed_space=&child->initial_fixed;
    }
    return (long)base;
}
RAW_FN _Noreturn void sucrune_fork_child_start(struct sucrune_fork_launch *launch,int channel,pid_t expected) {
    long arena=prepare_arena(launch,channel,expected,-1);
    if(arena<0) {
        int error=(int)arena;
        (void)raw(SYS_sendto,channel,(long)&error,sizeof(error),MSG_NOSIGNAL|MSG_DONTWAIT,0,0);
        die(125);
    }
    sucrune_fork_arena_enter((void *)arena);
}
RAW_FN long sucrune_vfork_child_start(const struct sucrune_fork_launch *launch,int channel,
                               pid_t expected,int writer,void **owned) {
    long arena=prepare_arena(launch,channel,expected,writer);
    if(arena<0) return arena;
    long child=sucrune_fork_raw_clone(CLONE_VM|SIGCHLD,(void *)((uintptr_t)arena+SUCRUNE_FORK_SUPERVISOR_TOP),
                                     sucrune_fork_arena_enter,(void *)arena);
    if(child<0) sucrune_vfork_release_arena((void *)arena);
    else *owned=(void *)arena;
    return child;
}
RAW_FN void sucrune_vfork_release_arena(void *arena) {
    if(arena) (void)R2(SYS_munmap,arena,(size_t)SUCRUNE_FORK_ARENA_BYTES+SUCRUNE_LINUX_MAX_FILE);
}
RAW_FN __attribute__((visibility("hidden"))) _Noreturn void sucrune_fork_supervisor(void) {
    struct sucrune_fork_launch *launch=active.launch;
    active.pid=(pid_t)R0(SYS_getpid);
    long result=raw(SYS_prctl,PR_SET_PDEATHSIG,SIGKILL,0,0,0,0);
    if(result<0 || R0(SYS_getppid)!=active.parent) fail(result<0 ? result : -ESRCH);
    if((launch->snapshot.flags&CLONE_CHILD_CLEARTID)!=0U) {
        result=R1(SYS_set_tid_address,launch->snapshot.child_tid);
        if(result<0) fail(result);
    }
    result=clean_descriptors();if(result<0) fail(result);
    /* Reserve native fd 0 with a CLOEXEC private alias. Never retain a guest
     * input reader here. All later guest aliases and startup FDs are >= 3. */
    result=R3(SYS_fcntl,0,F_GETFD,0);
    if(result==-EBADF) {result=R3(SYS_fcntl,launch->broker,F_DUPFD_CLOEXEC,0);if(result!=0) fail(result<0 ? result : -EIO);}
    else if(result<0) fail(result);
    if(launch->snapshot.scope_bus>=0) {
        active.scope_lease=sucrune_scope_join(launch->snapshot.scope_bus);
        if(active.scope_lease<0) fail(active.scope_lease);
        if(active.scope_lease<3) fail(-EBADF);
        uintptr_t monitor_stack=(uintptr_t)child_context()+0x110000U;
        result=sucrune_fork_raw_clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM,
            (void *)monitor_stack,sucrune_scope_monitor,(void *)(intptr_t)active.scope_lease);
        if(result<0) fail(result);
        /* Project ownership is established before the ordinary parent can exit. */
        result=raw(SYS_prctl,PR_SET_PDEATHSIG,0,0,0,0,0);
        if(result<0) fail(result);
    }
    if(!executable(launch->snapshot.cpu.pc) || !allowed(launch->snapshot.cpu.sp-16U,16U,1)) fail(-EFAULT);
    struct kernel_action action={sucrune_fork_signal_entry,SA_SIGINFO|SA_ONSTACK|0x04000000U,sucrune_fork_restorer,UINT64_MAX};
    for(int i=0;i<2;i++) {
        result=raw(SYS_rt_sigaction,i==0 ? SIGUSR2 : SIGSYS,(long)&action,0,8,0,0);
        if(result<0) fail(result);
    }
    uintptr_t stack=(uintptr_t)child_context()+SUCRUNE_FORK_WORKER_TOP;
    result=sucrune_fork_raw_clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM,
        (void *)stack,worker,NULL);
    if(result<0) fail(result);
    for(;;) {
        while(!__atomic_load_n(&active.exec_ready,__ATOMIC_ACQUIRE))
            (void)raw(SYS_futex,(long)&active.exec_ready,FUTEX_WAIT_PRIVATE,0,0,0,0);
        switch(active.exec_ready) {
        case 1: active.exec_result=replace_image(); break;
        case 2: active.exec_result=nested_fork_launch(); break;
        case 3: active.exec_result=R1(SYS_set_tid_address,active.requested_clear_tid); break;
        default: die(125);
        }
        __atomic_store_n(&active.exec_ready,0,__ATOMIC_RELEASE);
        (void)R3(SYS_futex,&active.exec_ready,FUTEX_WAKE_PRIVATE,1);
    }
}
#endif
