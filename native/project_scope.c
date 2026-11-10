#include "project_scope.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Fork bootstrap and shared-VM vfork cannot use Bionic's TLS or allocator. */
static inline long call(long n,long a,long b,long c,long d) {
#if defined(__aarch64__)
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x8) : "memory","cc");
    return x0;
#else
    long r=syscall(n,a,b,c,d,0,0); return r<0 ? -errno : r;
#endif
}
void sucrune_scope_name(const char *program) {
    const char *name=strrchr(program,'/');
    name=name?name+1:program;
    char path[64];
    snprintf(path,sizeof(path),"/proc/self/task/%d/comm",getpid());
    int fd=open(path,O_WRONLY|O_CLOEXEC);
    if (fd >= 0) {
        size_t length = strnlen(name, 15);
        ssize_t written;
        do {
            written = write(fd, name, length);
        } while (written < 0 && errno == EINTR);
        close(fd);
    }
}
/* Only the trusted native process receives external signals. Translate a
 * guest handler or mask into the existing pending/rt_sigreturn machinery. */
static unsigned int external_pending;
static void capture(int signo) {
    __atomic_fetch_or(&external_pending,1U<<(unsigned int)(signo-1),__ATOMIC_RELAXED);
}
void sucrune_scope_disposition(unsigned int sig,uint64_t handler,uint64_t mask) {
    if(sig!=SIGHUP && sig!=SIGTERM && sig!=SIGINT) return;
    struct sigaction action={0};
    sigemptyset(&action.sa_mask);
    action.sa_handler=handler==1U ? SIG_IGN : handler>1U || (mask&(UINT64_C(1)<<(sig-1))) ? capture : SIG_DFL;
    (void)sigaction((int)sig,&action,NULL);
}
unsigned int sucrune_scope_pending(void) {
    return __atomic_exchange_n(&external_pending,0,__ATOMIC_RELAXED);
}
enum action { JOIN=1, LIST, OPEN_PROC, SIGNAL };
struct request { int op,pid,value; };
struct reply { int result; int32_t pids[SUCRUNE_SCOPE_LIMIT]; };
static long transfer(int socket,void *data,size_t size,int *right,int send_packet) {
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    struct iovec vec={data,size};
    struct msghdr msg={.msg_iov=&vec,.msg_iovlen=1};
    if(right && (!send_packet || *right>=0)) {
        msg.msg_control=control.bytes; msg.msg_controllen=sizeof(control);
        if(send_packet) {
            struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
            c->cmsg_len=CMSG_LEN(sizeof(int)); c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS;
            *(int *)CMSG_DATA(c)=*right;
        } else *right=-1;
    }
    long got;
    do {got=call(send_packet?SYS_sendmsg:SYS_recvmsg,socket,(long)&msg,send_packet?MSG_NOSIGNAL:MSG_CMSG_CLOEXEC,0);} while(got==-EINTR);
    if(got>=0 && !send_packet && right && msg.msg_controllen) {
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
        if(!c || c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS || c->cmsg_len!=CMSG_LEN(sizeof(int))) return -EPROTO;
        *right=*(int *)CMSG_DATA(c);
    }
    return got;
}
/* The fresh private reply socket doubles as the lifetime lease on JOIN. */
static int request(int bus,struct request req,struct reply *out,int *right) {
    int ends[2];
    long rc=call(SYS_socketpair,AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,(long)ends);
    if(rc<0) return (int)rc;
    rc=transfer(bus,&req,sizeof(req),&ends[1],1);
    call(SYS_close,ends[1],0,0,0);
    if(rc==sizeof(req)) rc=transfer(ends[0],out,sizeof(*out),right,0);
    if(rc>=(long)sizeof(out->result) && req.op==JOIN && out->result==0) return ends[0];
    call(SYS_close,ends[0],0,0,0);
    if(rc<0) return (int)rc;
    if(rc<(long)sizeof(out->result)) return -EPIPE;
    if(req.op==LIST && out->result>=0 && (out->result>SUCRUNE_SCOPE_LIMIT ||
       rc!=(long)(sizeof(out->result)+(size_t)out->result*sizeof(out->pids[0])))) return -EPROTO;
    return out->result;
}
int sucrune_scope_join(int bus) {
    struct reply out; return request(bus,(struct request){JOIN,0,0},&out,NULL);
}
int sucrune_scope_pids(int bus,int32_t *pids,size_t capacity) {
    struct reply out; int count=request(bus,(struct request){LIST,0,0},&out,NULL);
    if(count<0) return count;
    if((size_t)count>capacity) return -EOVERFLOW;
    for(int i=0;i<count;i++) pids[i]=out.pids[i];
    return count;
}
int sucrune_scope_proc(int bus,int32_t pid,int file) {
    struct reply out; int fd=-1;
    int rc=request(bus,(struct request){OPEN_PROC,pid,file},&out,&fd);
    if(rc<0 || fd<0) { if(fd>=0) call(SYS_close,fd,0,0,0); return rc<0?rc:-EPROTO; }
    return fd;
}
int sucrune_scope_signal(int bus,int32_t pid,int signo) {
    struct reply out; return request(bus,(struct request){SIGNAL,pid,signo},&out,NULL);
}
void sucrune_scope_monitor(void *opaque) {
    int fd=(int)(intptr_t)opaque;
    for(;;) {
        int sig=0;
        struct iovec vec={&sig,sizeof(sig)};
        struct msghdr msg={.msg_iov=&vec,.msg_iovlen=1};
        long n=call(SYS_recvmsg,fd,(long)&msg,0,0);
        if(n==-EINTR) continue;
        /* The server owns all lease senders. Its death revokes the project
         * even if the Java subreaper is killed simultaneously. */
        if(n!=sizeof(sig)) sig=SIGKILL;
        if(sig==SIGKILL || sig==SIGTERM || sig==SIGINT || sig==SIGHUP) {
            uint64_t mask=UINT64_C(1)<<(sig-1);
            call(SYS_rt_sigprocmask,SIG_UNBLOCK,(long)&mask,0,sizeof(mask));
            call(SYS_kill,call(SYS_getpid,0,0,0,0),sig,0,0);
        }
    }
}
static void *monitor(void *arg) { sucrune_scope_monitor(arg); return NULL; }
int sucrune_scope_watch(int lease) {
    pthread_t thread; int err=pthread_create(&thread,NULL,monitor,(void *)(intptr_t)lease);
    if(!err) pthread_detach(thread);
    return -err;
}
struct member { int lease,dir; pid_t pid; };
static int serve_one(int bus,struct member *members) {
    struct request req; int peer=-1;
    long n=transfer(bus,&req,sizeof(req),&peer,0);
    if(n<=0) return 0;
    if(peer<0) return 1;
    struct ucred credentials;
    socklen_t size=sizeof(credentials);
    struct reply reply={.result=-ESRCH}; int right=-1,store=-1;
    if(n==sizeof(req) && getsockopt(peer,SOL_SOCKET,SO_PEERCRED,&credentials,&size)==0 && size==sizeof(credentials) && credentials.uid==getuid()) {
        if(req.op==LIST) reply.result=0;
        if(req.op==JOIN) reply.result=-EAGAIN;
        for(int i=0;i<SUCRUNE_SCOPE_LIMIT;i++) {
            struct member *m=&members[i];
            if(m->lease>=0) {
                struct pollfd l={m->lease,POLLIN,0};
                if(poll(&l,1,0)>0 && (l.revents&(POLLHUP|POLLERR))) {
                    close(m->lease); close(m->dir); m->lease=-1;
                }
            }
            if(m->lease<0) { if(store<0) store=i; continue; }
            if(req.op==LIST) reply.pids[reply.result++]=m->pid;
            else if(req.op==JOIN && m->pid==credentials.pid) {reply.result=-EEXIST;break;}
            else if(req.pid==m->pid && req.op==OPEN_PROC && req.value>=0 && req.value<=2) {
                right=req.value==0 ? fcntl(m->dir,F_DUPFD_CLOEXEC,3) :
                    openat(m->dir,"stat",O_CLOEXEC|O_NOFOLLOW|(req.value==1?O_RDONLY:O_PATH));
                reply.result=right<0?-errno:0; break;
            } else if(req.op==SIGNAL && (req.pid==m->pid || (req.pid < -1 && req.pid!=INT32_MIN && getpgid(m->pid)==-req.pid))) {
                int sig=req.value;
                if(sig==0) reply.result=0;
                else if(sig==SIGKILL || sig==SIGTERM || sig==SIGINT || sig==SIGHUP) {
                    reply.result=send(m->lease,&sig,sizeof(sig),MSG_DONTWAIT|MSG_NOSIGNAL)==sizeof(sig)?0:-errno;
                } else reply.result=-EOPNOTSUPP;
                if(req.pid>0) break;
            }
        }
        if(req.op==JOIN && store>=0 && reply.result==-EAGAIN && credentials.pid!=getpid()) {
            char path[64]; snprintf(path,sizeof(path),"/proc/%d",credentials.pid);
            int dir=open(path,O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW|O_PATH);
            if(dir>=0) {
                members[store]=(struct member){peer,dir,credentials.pid};
                reply.result=0;
            } else reply.result=-errno;
        }
    }
    size_t length=sizeof(reply.result);
    if(req.op==LIST && reply.result>0) length+=(size_t)reply.result*sizeof(reply.pids[0]);
    (void)transfer(peer,&reply,length,&right,1);
    if(right>=0) close(right);
    if(req.op!=JOIN || reply.result!=0) close(peer);
    return 1;
}
static void *serve(void *opaque) {
    int bus=(int)(intptr_t)opaque;
    struct member members[SUCRUNE_SCOPE_LIMIT];
    for(int i=0;i<SUCRUNE_SCOPE_LIMIT;i++) members[i].lease=-1;
    while(serve_one(bus,members)) {}
    close(bus);
    for(int i=0;i<SUCRUNE_SCOPE_LIMIT;i++) if(members[i].lease>=0) {close(members[i].lease); close(members[i].dir);}
    return NULL;
}
int sucrune_scope_start(void) {
    int ends[2];
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,ends)) return -errno;
    pthread_t thread; int err=pthread_create(&thread,NULL,serve,(void *)(intptr_t)ends[1]);
    if(err) { close(ends[0]);close(ends[1]);return -err; }
    pthread_detach(thread); return ends[0];
}
