#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid, child_status, child_events;
static void changed(int number,siginfo_t *info,void *context) {
    (void)context;
    if(number==SIGCHLD && info!=NULL && info->si_code==CLD_EXITED) {
        child_pid=info->si_pid;child_status=info->si_status;child_events++;
    }
}
static long select_raw(int nfds,uint64_t *readable,uint64_t *writable,uint64_t *exception,
        struct timespec *timeout,const uint64_t *change) {
    return syscall(SYS_pselect6,nfds,readable,writable,exception,timeout,change);
}
int main(void) {
    int fd=eventfd(1,EFD_CLOEXEC|EFD_NONBLOCK);
    if(fd<0 || fd>=64) return 51;
    uint64_t bit=UINT64_C(1)<<(unsigned int)fd,r=bit,w=bit,x=bit;
    struct timespec time={0,0};
    if(select_raw(fd+1,&r,&w,&x,&time,NULL)!=2 || r!=bit || w!=bit || x!=0) return 52;
    uint64_t counter=0;
    if(read(fd,&counter,sizeof(counter))!=sizeof(counter) || counter!=1) return 53;
    r=bit;
    if(select_raw(fd+1,&r,NULL,NULL,&time,NULL)!=0 || r!=0) return 54;
    if(close(fd)!=0) return 55;
    r=bit;
    if(select_raw(fd+1,&r,NULL,NULL,&time,NULL)!=-1 || errno!=EBADF || r!=bit) return 56;
    uint64_t high[2]={0,1};
    if(select_raw(65,high,NULL,NULL,&time,NULL)!=-1 || errno!=EBADF || high[1]!=1) return 57;
    uint64_t empty=0,pair[2]={(uint64_t)(uintptr_t)&empty,128};
    if(select_raw(0,NULL,NULL,NULL,&time,pair)!=-1 || errno!=EINVAL) return 58;
    pair[1]=8;
    struct timespec before,after;
    time=(struct timespec){0,2000000};
    if(clock_gettime(CLOCK_MONOTONIC,&before)!=0 || select_raw(0,NULL,NULL,NULL,&time,pair)!=0 ||
        clock_gettime(CLOCK_MONOTONIC,&after)!=0 || time.tv_sec!=0 || time.tv_nsec!=0 ||
        (after.tv_sec-before.tv_sec)*1000000000L+after.tv_nsec-before.tv_nsec<1000000L) return 59;
    struct sigaction action;
    memset(&action,0,sizeof(action));action.sa_sigaction=changed;action.sa_flags=SA_SIGINFO;
    if(sigaction(SIGCHLD,&action,NULL)<0) return 60;
    uint64_t block=UINT64_C(1)<<(SIGCHLD-1),saved=0,mask=0;
    if(syscall(SYS_rt_sigprocmask,SIG_BLOCK,&block,&saved,8)!=0) return 61;
    long child=syscall(SYS_clone,SIGCHLD,0,0,0,0);
    if(child==0) _exit(41);
    if(child<0) return 62;
    time=(struct timespec){3,0};
    if(select_raw(0,NULL,NULL,NULL,&time,pair)!=-1 || errno!=EINTR ||
        child_events!=1 || child_pid!=child || child_status!=41) return 63;
    if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,NULL,&mask,8)!=0 || (mask&block)==0 ||
        syscall(SYS_rt_sigprocmask,SIG_SETMASK,&saved,NULL,8)!=0) return 64;
    int status=0;
    if(waitpid((pid_t)child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=41) return 65;
    const char line[]="pselect-ready-timeout-mask-child-ok\n";
    return write(1,line,sizeof(line)-1)==(ssize_t)(sizeof(line)-1) ? 0 : 66;
}
