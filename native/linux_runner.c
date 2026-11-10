#include "linux_runner.h"
#include "guest_exec_receive.h"
#include "process_probe.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(SUCRUNE_RUNNER_EXECUTABLE)
#include "shell_runtime.h"
#else
#include <dlfcn.h>
#include <dirent.h>
#include <poll.h>
#include <time.h>
#endif

#define RUNNER_MAGIC 0x5355524eU
#define RUNNER_VERSION 1U
#define RUNNER_ARG_LIMIT 64U
#define RUNNER_STRING_LIMIT 4096U
#define RUNNER_PATH_LIMIT 1024U
#define RUNNER_CONTROL_FD 7
#define RUNNER_INPUT_FD 6
#define RUNNER_FD_SCAN_LIMIT 16384U
enum runner_stage { ST_ARGUMENTS=1, ST_PATH, ST_SOCKET, ST_DUP, ST_FORK, ST_PDEATH,
    ST_FD_SCAN, ST_EXEC, ST_PROTOCOL, ST_REPORT, ST_WAIT, ST_SIGNAL, ST_STOP, ST_REAPER };
enum reply_kind { REPLY_REPORT=1, REPLY_ERROR=2 };
struct runner_start {
    uint32_t magic, version, text_size, argc, envc, has_input, reserved[2];
};
struct runner_reply {
    uint32_t magic, version, kind, size;
    int32_t status, error;
    uint32_t stage, reserved;
};
_Static_assert(sizeof(struct runner_start)==32U,"runner startup header ABI");
_Static_assert(sizeof(struct runner_reply)==32U,"runner reply header ABI");
struct runner_message { struct runner_start header; char text[SUCRUNE_RUNNER_TEXT_LIMIT]; };

static ssize_t send_parts(int fd, const void *header, size_t header_size, const void *body, size_t body_size) {
    struct iovec parts[2] = {{.iov_base=(void *)header,.iov_len=header_size}, {.iov_base=(void *)body,.iov_len=body_size}};
    struct msghdr message = {.msg_iov=parts,.msg_iovlen=body_size == 0U ? 1U : 2U};
    ssize_t result;
    do { result=sendmsg(fd,&message,MSG_NOSIGNAL); } while(result<0 && errno==EINTR);
    return result;
}
static ssize_t receive_packet(int fd, void *bytes, size_t size) {
    ssize_t result;
    do { result=recv(fd,bytes,size,MSG_TRUNC); } while(result<0 && errno==EINTR);
    return result;
}

#if !defined(SUCRUNE_RUNNER_EXECUTABLE)
const char *sucrune_linux_runner_path(void) { return NULL; }
const struct sucrune_guest_exec *sucrune_linux_exec_state(void) { return NULL; }
int sucrune_linux_is_runner(void) { return 0; }
_Noreturn void sucrune_linux_exit_group(const char *report) { (void)report; _exit(126); }
static const char *stage_name(enum runner_stage stage) {
    switch(stage) {
        case ST_ARGUMENTS:return "runner_arguments"; case ST_PATH:return "runner_path";
        case ST_SOCKET:return "runner_socket"; case ST_DUP:return "runner_descriptor";
        case ST_FORK:return "runner_fork"; case ST_PDEATH:return "runner_parent_death";
        case ST_FD_SCAN:return "runner_fd_cleanup"; case ST_EXEC:return "runner_execve";
        case ST_PROTOCOL:return "runner_protocol"; case ST_REPORT:return "runner_report";
        case ST_WAIT:return "runner_wait"; case ST_SIGNAL:return "runner_signal";
        case ST_STOP:return "runner_stopped"; case ST_REAPER:return "runner_subreaper";
    }
    return "runner_unknown";
}
struct child_cleanup { unsigned int reaped; int complete, stopped; pid_t last_reaped; };
static int failure(char *report,size_t capacity,enum runner_stage stage,int error,pid_t child,int waited,int status,
        const struct child_cleanup *children) {
    if(report!=NULL && capacity!=0U) (void)snprintf(report,capacity,
        "{\"schema_version\":1,\"kind\":\"linux\",\"status\":\"failed\",\"stage\":\"%s\","
        "\"message\":\"The packaged Linux runner did not complete.\",\"error_number\":%d,"
        "\"runner_pid\":%ld,\"runner_parent_pid\":%ld,\"runner_waited\":%s,\"runner_exit_code\":%d,\"runner_signal\":%d,"
        "\"stop_requested\":%s,\"descendants_reaped\":%u,\"last_reaped_descendant_pid\":%ld,\"descendant_wait_complete\":%s}",
        stage_name(stage),error,(long)child,(long)getpid(),waited ? "true" : "false",
        waited && WIFEXITED(status) ? WEXITSTATUS(status) : -1,waited && WIFSIGNALED(status) ? WTERMSIG(status) : 0,
        children->stopped ? "true" : "false",children->reaped,(long)children->last_reaped,children->complete ? "true" : "false");
    return 1;
}
static int add_string(struct runner_message *packet,const char *text,size_t limit) {
    if(text==NULL) return -EINVAL;
    size_t length=strnlen(text,limit);
    if(length==limit || length+1U>SUCRUNE_RUNNER_TEXT_LIMIT-packet->header.text_size) return -E2BIG;
    memcpy(packet->text+packet->header.text_size,text,length+1U);
    packet->header.text_size+=(uint32_t)(length+1U);
    return 0;
}
static int runner_path(char *path,size_t capacity) {
    Dl_info library;
    if(dladdr((const void *)(uintptr_t)&sucrune_linux_spawn,&library)==0 || library.dli_fname==NULL ||
       library.dli_fname[0]!='/' || strstr(library.dli_fname,"!/")!=NULL) return -ENOEXEC;
    const char *slash=strrchr(library.dli_fname,'/');
    if(slash==NULL) return -ENOEXEC;
    size_t prefix=(size_t)(slash-library.dli_fname)+1U;
    if(prefix>capacity || sizeof(SUCRUNE_RUNNER_FILE)>capacity-prefix) return -ENAMETOOLONG;
    memcpy(path,library.dli_fname,prefix);
    memcpy(path+prefix,SUCRUNE_RUNNER_FILE,sizeof(SUCRUNE_RUNNER_FILE));
    return 0;
}

/* Everything below on the fork-child path is bounded stack work and low-level
 * syscalls. No allocator, stdio, JNI, dlopen, opendir/readdir or guest runtime is
 * entered until successful exec has discarded ART and its inherited locks. */
static _Noreturn void child_failure(int control,enum runner_stage stage,int error) {
    struct runner_reply reply={.magic=RUNNER_MAGIC,.version=RUNNER_VERSION,.kind=REPLY_ERROR,
        .status=1,.error=error,.stage=(uint32_t)stage};
    (void)syscall(SYS_sendto,control,&reply,sizeof(reply),MSG_NOSIGNAL,NULL,0);
    _exit(125);
}
struct runner_dirent { uint64_t inode; int64_t offset; uint16_t length; unsigned char type; char name[]; };
static int keep_fd(int fd,int scan,int input) {
    return fd==scan || fd==1 || fd==2 || fd==3 || fd==4 || fd==5 || fd==RUNNER_CONTROL_FD ||
        (input && fd==RUNNER_INPUT_FD);
}
static int clean_child_fds(int input) {
    (void)close(0);
    int scan=(int)syscall(SYS_openat,AT_FDCWD,"/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC,0);
    if(scan<0) return errno;
    union { uint64_t alignment; unsigned char data[4096]; } buffer;
    /* proc fd iteration uses numeric d_off, so closed entries do not shift
     * remaining descriptors. A second bounded scan verifies no missed FDs. */
    for(unsigned int pass=0U;pass<2U;pass++) {
        unsigned int entries=0U;
        for(;;) {
            long received=syscall(SYS_getdents64,scan,buffer.data,sizeof(buffer.data));
            if(received<0) {int error=errno;(void)close(scan);return error;}
            if(received==0) break;
            size_t offset=0U;
            while(offset<(size_t)received) {
                if((size_t)received-offset<offsetof(struct runner_dirent,name)+1U) {(void)close(scan);return EIO;}
                const struct runner_dirent *entry=(const struct runner_dirent *)(const void *)(buffer.data+offset);
                size_t size=entry->length;
                if(size<offsetof(struct runner_dirent,name)+1U || size>(size_t)received-offset || ++entries>RUNNER_FD_SCAN_LIMIT) {
                    (void)close(scan);return EOVERFLOW;
                }
                size_t count=size - offsetof(struct runner_dirent,name), index=0U;
                int fd=0, numeric=1;
                while(index<count && entry->name[index]!='\0') {
                    unsigned char digit=(unsigned char)entry->name[index++];
                    if(digit<'0' || digit>'9' || fd>(INT_MAX-(int)(digit-'0'))/10) {numeric=0;break;}
                    fd=fd*10+(int)(digit-'0');
                }
                if(index==count) {(void)close(scan);return EIO;}
                if(numeric && index!=0U && !keep_fd(fd,scan,input)) {
                    if(close(fd)!=0 && errno!=EBADF && errno!=EINTR) {int error=errno;(void)close(scan);return error;}
                }
                offset+=size;
            }
        }
        if(pass==0U && lseek(scan,0,SEEK_SET)<0) {int error=errno;(void)close(scan);return error;}
    }
    (void)close(scan);
    return 0;
}
static _Noreturn void child_exec(const char *path,char *const *arguments,char *const *environment,
        const int *sources,int has_input,pid_t expected_parent) {
    int control=sources[4];
    if(syscall(SYS_prctl,PR_SET_PDEATHSIG,SIGKILL,0,0,0)!=0)
        child_failure(control,ST_PDEATH,errno);
    if(getppid()!=expected_parent) child_failure(control,ST_PDEATH,ESRCH);
    for(int i=0;i<5;i++) {
        if(i==3 && !has_input) continue;
        if(dup3(sources[i],i+3,0)<0) child_failure(control,ST_DUP,errno);
    }
    control=RUNNER_CONTROL_FD;
    if(!has_input) (void)close(RUNNER_INPUT_FD);
    /* Keep linker diagnostics, but never create an extra stdin reader on fd0. */
    if(dup3(4,1,0)<0 || dup3(5,2,0)<0) child_failure(control,ST_DUP,errno);
    int error=clean_child_fds(has_input);
    if(error!=0) child_failure(control,ST_FD_SCAN,error);
    execve(path,arguments,environment);
    child_failure(control,ST_EXEC,errno);
}

/* JNI runs in one unique isolated worker with no other child launchers. Never
 * consume an existing child during preflight, and never signal an arbitrary PID
 * from procfs. waitid(...WNOWAIT) checks the exact candidate is ours before
 * kill; no other code in the wrapper waits for children. */
static int no_existing_children(void) {
    siginfo_t info;
    int result;
    do { result=waitid(P_ALL,0,&info,WEXITED|WNOHANG|WNOWAIT); } while(result<0 && errno==EINTR);
    return result<0 && errno==ECHILD ? 0 : result<0 ? errno : EBUSY;
}
static int64_t monotonic_ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)!=0) return -1;
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void kill_if_adopted(long candidate) {
    if(candidate<=0 || candidate>INT_MAX) return;
    siginfo_t info={0};
    int rc;
    do { rc=waitid(P_PID,(id_t)candidate,&info,WEXITED|WNOHANG|WNOWAIT); } while(rc<0 && errno==EINTR);
    if(rc==0 && info.si_pid==0) (void)kill((pid_t)candidate,SIGKILL);
}
static void kill_adopted_children(void) {
    /* Numeric directory entries are candidate identifiers only. No status,
     * identity, command line or other process data is read or retained. This
     * works on kernels built without /proc/PID/task/TID/children. */
    DIR *tasks=opendir("/proc");
    if(tasks==NULL) return; /* PDEATHSIG cascade also works without procfs. */
    struct dirent *entry;
    while((entry=readdir(tasks))!=NULL) {
        const char *name=entry->d_name;
        size_t digits=strspn(name,"0123456789");
        if(digits==0U || digits>10U || name[digits]!='\0') continue;
        kill_if_adopted(strtol(name,NULL,10));
    }
    (void)closedir(tasks);
}
static int reap_adopted(struct child_cleanup *children) {
    const int64_t start=monotonic_ms();
    if(start<0) return EIO;
    int64_t next_sweep=start+30;
    for(;;) {
        int status;
        pid_t child=waitpid(-1,&status,WNOHANG);
        if(child>0) { children->reaped++; children->last_reaped=child; continue; }
        if(child<0 && errno==EINTR) continue;
        if(child<0 && errno==ECHILD) { children->complete=1; return 0; }
        if(child<0) return errno;
        int64_t now=monotonic_ms();
        if(now<0 || now-start>=4000) return ETIMEDOUT;
        if(now>=next_sweep) { kill_adopted_children(); next_sweep=now+50; }
        (void)poll(NULL,0,5);
    }
}
static int stop_or_report(int report_socket,int stop,pid_t runner,int project_scope) {
    struct pollfd fds[2]={{report_socket,POLLIN,0},{stop,POLLIN,0}};
    int ready;
    for(;;) {
        ready=poll(fds,2,project_scope?1000:-1);
        if(ready<0 && errno==EINTR) continue;
        if(ready!=0) break;
        /* Only this isolated wrapper reaps orphans. Preserve the main runner
         * status and never race wait4 in any still-living guest shell. */
        for(;;) {
            siginfo_t child={0};
            if(waitid(P_ALL,0,&child,WEXITED|WNOHANG|WNOWAIT)!=0 || child.si_pid<=0 || child.si_pid==runner) break;
            (void)waitpid(child.si_pid,NULL,WNOHANG);
        }
    }
    if(ready<0) return errno;
    if((fds[1].revents&POLLNVAL)!=0) return EBADF;
    return fds[1].revents!=0 ? ECANCELED : 0;
}
static int wait_direct(pid_t child,int stop,int *status,struct child_cleanup *children) {
    for(;;) {
        pid_t reaped=waitpid(child,status,WNOHANG);
        if(reaped==child) return 0;
        if(reaped<0 && errno==EINTR) continue;
        if(reaped<0) return errno;
        if(children->stopped) { (void)poll(NULL,0,5); continue; }
        struct pollfd watch={stop,POLLIN,0};
        int ready=poll(&watch,1,5);
        if(ready<0 && errno==EINTR) continue;
        if(ready<0 || (watch.revents&POLLNVAL)!=0) return ready<0 ? errno : EBADF;
        if(ready>0) { children->stopped=1; (void)kill(child,SIGKILL); }
    }
}
int sucrune_linux_spawn(int broker,const char *path,size_t argc,const char *const *argv,
        size_t envc,const char *const *envp,const char *cwd,int output,int error_output,
        char *report,size_t capacity,int input,int stop) {
    int sockets[2]={-1,-1}, sources[5]={-1,-1,-1,-1,-1};
    int error=EINVAL, status=0, waited=0, result=1;
    int old_reaper=0, reaper_set=0;
    struct child_cleanup children={0};
    enum runner_stage stage=ST_ARGUMENTS;
    pid_t child=-1;
    struct runner_message *packet=NULL;
    if(report==NULL || capacity<512U || broker<0 || output<0 || error_output<0 || stop<0 || path==NULL ||
        path[0]!='/' || argc>RUNNER_ARG_LIMIT || envc>RUNNER_ARG_LIMIT ||
        (argc!=0U && argv==NULL) || (envc!=0U && envp==NULL)) goto done;
    packet=calloc(1U,sizeof(*packet));
    if(packet==NULL) {error=ENOMEM;goto done;}
    packet->header=(struct runner_start){.magic=RUNNER_MAGIC,.version=RUNNER_VERSION,
        .argc=(uint32_t)argc,.envc=(uint32_t)envc,.has_input=input>=0 ? 1U : 0U};
    error=add_string(packet,path,RUNNER_PATH_LIMIT);
    if(error==0) error=add_string(packet,cwd,RUNNER_PATH_LIMIT);
    for(size_t i=0;error==0 && i<argc;i++) error=add_string(packet,argv[i],RUNNER_STRING_LIMIT+1U);
    for(size_t i=0;error==0 && i<envc;i++) error=add_string(packet,envp[i],RUNNER_STRING_LIMIT+1U);
    if(error<0) {error=-error;goto done;}
    char executable[PATH_MAX], parent_text[32];
    error=runner_path(executable,sizeof(executable));
    if(error<0) {stage=ST_PATH;error=-error;goto done;}
    pid_t parent=getpid();
    (void)snprintf(parent_text,sizeof(parent_text),"%ld",(long)parent);
    char *arguments[]={executable,"--sucrune-runner-v1","7",parent_text,NULL};
    char *environment[]={"LANG=C","PATH=/system/bin",NULL};
    sigset_t blocked; (void)sigfillset(&blocked);
    struct sigaction child_action;
    if(sigaction(SIGCHLD,NULL,&child_action)!=0) {stage=ST_WAIT;error=errno;goto done;}
    if(child_action.sa_handler!=SIG_DFL || (child_action.sa_flags&SA_NOCLDWAIT)!=0) {stage=ST_WAIT;error=ENOTSUP;goto done;}
    error=no_existing_children();
    if(error!=0) {stage=ST_REAPER;goto done;}
    if(prctl(PR_GET_CHILD_SUBREAPER,&old_reaper,0UL,0UL,0UL)!=0 ||
       prctl(PR_SET_CHILD_SUBREAPER,1UL,0UL,0UL,0UL)!=0) {stage=ST_REAPER;error=errno;goto done;}
    reaper_set=1;
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,sockets)!=0) {stage=ST_SOCKET;error=errno;goto done;}
    int buffer_size=(int)(2U*sizeof(*packet));
    for(int i=0;i<2;i++) {
        if(setsockopt(sockets[i],SOL_SOCKET,SO_SNDBUF,&buffer_size,sizeof(buffer_size))!=0 ||
           setsockopt(sockets[i],SOL_SOCKET,SO_RCVBUF,&buffer_size,sizeof(buffer_size))!=0) {stage=ST_SOCKET;error=errno;goto done;}
    }
    int originals[5]={broker,output,error_output,input,sockets[1]};
    for(int i=0;i<5;i++) {
        if(originals[i]<0) continue;
        sources[i]=fcntl(originals[i],F_DUPFD_CLOEXEC,16);
        if(sources[i]<0) {stage=ST_DUP;error=errno;goto done;}
    }
    /* Block before fork: the child must never enter an inherited ART signal
     * handler, even in the short window before its first child_exec syscall. */
    sigset_t previous_mask;
    if(sigprocmask(SIG_SETMASK,&blocked,&previous_mask)!=0) {stage=ST_SIGNAL;error=errno;goto done;}
    child=fork();
    int fork_error=errno;
    if(child==0) child_exec(executable,arguments,environment,sources,input>=0,parent);
    int mask_error=sigprocmask(SIG_SETMASK,&previous_mask,NULL)==0 ? 0 : errno;
    if(child<0) {stage=ST_FORK;error=fork_error;goto done;}
    /* Close all parent copies of the transferred reader before startup send. */
    if(input>=0) {(void)close(input);input=-1;}
    for(int i=0;i<5;i++) {if(sources[i]>=0) {(void)close(sources[i]);sources[i]=-1;}}
    (void)close(sockets[1]);sockets[1]=-1;
    if(mask_error!=0) {stage=ST_SIGNAL;error=mask_error;(void)kill(child,SIGKILL);goto reap;}
    size_t startup_size=sizeof(packet->header)+packet->header.text_size;
    if(send_parts(sockets[0],&packet->header,sizeof(packet->header),packet->text,packet->header.text_size)!=(ssize_t)startup_size) {
        stage=ST_PROTOCOL;error=errno==0 ? EIO : errno;(void)kill(child,SIGKILL);goto reap;
    }
    unsigned char response[sizeof(struct runner_reply)+SUCRUNE_RUNNER_REPORT_LIMIT];
    int scoped=0;
    for(size_t i=0;i<envc;i++) if(!strcmp(envp[i],"SUCRUNE_PROCESS_SCOPE=project")) scoped=1;
    error=stop_or_report(sockets[0],stop,child,scoped);
    if(error!=0) {
        children.stopped=error==ECANCELED;
        stage=children.stopped ? ST_STOP : ST_WAIT;
        (void)kill(child,SIGKILL);goto reap;
    }
    ssize_t received=receive_packet(sockets[0],response,sizeof(response));
    if(received<(ssize_t)sizeof(struct runner_reply) || received>(ssize_t)sizeof(response)) {
        stage=ST_REPORT;error=received<0 ? errno : EIO;(void)kill(child,SIGKILL);goto reap;
    }
    struct runner_reply reply;memcpy(&reply,response,sizeof(reply));
    if(reply.magic!=RUNNER_MAGIC || reply.version!=RUNNER_VERSION || reply.reserved!=0U ||
       reply.size>=SUCRUNE_RUNNER_REPORT_LIMIT || (size_t)received!=sizeof(reply)+reply.size) {
        stage=ST_PROTOCOL;error=EPROTO;(void)kill(child,SIGKILL);goto reap;
    }
    if(reply.kind==REPLY_ERROR && reply.size==0U) {
        stage=reply.stage>=ST_ARGUMENTS && reply.stage<=ST_SIGNAL ? (enum runner_stage)reply.stage : ST_PROTOCOL;
        error=reply.error>0 ? reply.error : EIO;goto reap;
    }
    const char *body=(const char *)response+sizeof(reply);
    if(reply.kind!=REPLY_REPORT || reply.size<2U || body[0]!='{' || body[reply.size-1U]!='}' ||
       memchr(body,0,reply.size)!=NULL || (reply.status!=0 && reply.status!=1)) {
        stage=ST_PROTOCOL;error=EPROTO;(void)kill(child,SIGKILL);goto reap;
    }
    error=wait_direct(child,stop,&status,&children);
    if(error!=0) {stage=ST_WAIT;goto done;}
    waited=1;
    if(children.stopped) {stage=ST_STOP;error=ECANCELED;goto done;}
    if(!WIFEXITED(status) || WEXITSTATUS(status)!=reply.status) {stage=ST_SIGNAL;error=EIO;goto done;}
    error=reap_adopted(&children);
    if(error!=0) {stage=ST_REAPER;goto done;}
    {
        char suffix[320];
        int added=snprintf(suffix,sizeof(suffix),",\"runner_pid\":%ld,\"runner_parent_pid\":%ld,\"runner_waited\":true,\"runner_exit_code\":%d,"
            "\"stop_requested\":false,\"descendants_reaped\":%u,\"last_reaped_descendant_pid\":%ld,\"descendant_wait_complete\":true}",
            (long)child,(long)parent,WEXITSTATUS(status),children.reaped,(long)children.last_reaped);
        size_t prefix=reply.size-1U;
        if(added<0 || (size_t)added>=sizeof(suffix) || prefix+(size_t)added+1U>capacity ||
           prefix+(size_t)added+1U>SUCRUNE_RUNNER_REPORT_LIMIT) {stage=ST_REPORT;error=EOVERFLOW;goto done;}
        memcpy(report,body,prefix);memcpy(report+prefix,suffix,(size_t)added+1U);result=reply.status;
    }
    goto clean;
reap:
    {
        int e=wait_direct(child,stop,&status,&children);
        if(e==0) waited=1;
        else {stage=ST_WAIT;error=e;}
    }
done:
    if(waited && !children.complete && stage!=ST_REAPER) {
        int e=reap_adopted(&children); if(e!=0) {stage=ST_REAPER;error=e;}
    }
    result=failure(report,capacity,stage,error,child,waited,status,&children);
clean:
    if(reaper_set && prctl(PR_SET_CHILD_SUBREAPER,(unsigned long)old_reaper,0UL,0UL,0UL)!=0)
        result=failure(report,capacity,ST_REAPER,errno,child,waited,status,&children);
    if(input>=0) (void)close(input);
    for(int i=0;i<5;i++) if(sources[i]>=0) (void)close(sources[i]);
    for(int i=0;i<2;i++) if(sockets[i]>=0) (void)close(sockets[i]);
    free(packet);
    return result;
}

#else
int sucrune_linux_is_runner(void) { return 1; }
static char installed_runner[PATH_MAX];
static const struct sucrune_guest_exec *exec_state;
const char *sucrune_linux_runner_path(void) { return installed_runner[0]!='\0' ? installed_runner : NULL; }
const struct sucrune_guest_exec *sucrune_linux_exec_state(void) { return exec_state; }
static int runner_decimal(const char *text,int minimum) {
    if (!text || !*text) return -1;
    int value=0;
    while (*text) {
        if (*text<'0' || *text>'9' || value>(INT_MAX-(*text-'0'))/10) return -1;
        value=value*10+(*text++-'0');
    }
    return value>=minimum ? value : -1;
}
static int child_guest_exec(const char *channel,const char *parent) {
    int fd=runner_decimal(channel,3);
    int expected=runner_decimal(parent,1);
    if (fd<0 || expected<0) return 126;
    sigset_t empty; sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK,&empty,NULL)!=0) return 126;
    struct sucrune_guest_exec *packet=malloc(sizeof(*packet));
    if (!packet) return 126;
    ssize_t n=receive_packet(fd,packet,sizeof(*packet));
    const char *path=NULL,*argv[SUCRUNE_GUEST_EXEC_ARGS],*envp[SUCRUNE_GUEST_EXEC_ENV];
    if (n<0 || (size_t)n>sizeof(*packet) ||
        sucrune_exec_check_packet(packet,(size_t)n,fd,&path,argv,envp)!=0) return 126;
    if (packet->scope.bus<0) {
        if (prctl(PR_SET_PDEATHSIG,SIGKILL,0UL,0UL,0UL)!=0 || getppid()!=expected) return 126;
    } else if (fcntl(packet->scope.bus,F_SETFD,FD_CLOEXEC)<0 || fcntl(packet->scope.lease,F_SETFD,FD_CLOEXEC)<0 ||
               sucrune_scope_watch(packet->scope.lease)<0) return 126;
    (void)close(fd);
    if (fcntl(packet->broker,F_SETFD,FD_CLOEXEC)<0 || fcntl(packet->image_fd,F_SETFD,FD_CLOEXEC)<0 ||
        (packet->interp_fd>=0 && fcntl(packet->interp_fd,F_SETFD,FD_CLOEXEC)<0)) return 126;
    exec_state=packet;
    char report[SUCRUNE_RUNNER_REPORT_LIMIT];
    (void)sucrune_linux_run(packet->broker,path,packet->argc,argv,packet->envc,envp,"/",1,2,report,sizeof(report),-1);
    return 126; // The guest leaves via sucrune_exec_child_exit on its real PID.
}
_Noreturn void sucrune_linux_exit_group(const char *report) {
    size_t length = strnlen(report, SUCRUNE_RUNNER_REPORT_LIMIT);
    if (length < SUCRUNE_RUNNER_REPORT_LIMIT) {
        struct runner_reply reply = {.magic=RUNNER_MAGIC,.version=RUNNER_VERSION,.kind=REPLY_REPORT,
            .size=(uint32_t)length,.status=0};
        (void)send_parts(RUNNER_CONTROL_FD, &reply, sizeof(reply), report, length);
    }
    /* Keep stdout/stderr aliases alive until the kernel removes every thread;
     * their EOF and parent waitpid remain the externally observed barriers. */
    _exit(0);
}
static int runner_error(enum runner_stage stage,int error) {
    struct runner_reply reply={.magic=RUNNER_MAGIC,.version=RUNNER_VERSION,.kind=REPLY_ERROR,
        .status=1,.error=error,.stage=(uint32_t)stage};
    (void)send_parts(RUNNER_CONTROL_FD,&reply,sizeof(reply),NULL,0U);
    return 1;
}
static const char *take_string(struct runner_message *packet,size_t *position,size_t limit) {
    if(*position>=packet->header.text_size) return NULL;
    size_t remaining=packet->header.text_size-*position;
    const char *value=packet->text+*position;
    const char *end=memchr(value,0,remaining);
    if(end==NULL || (size_t)(end-value)>=limit) return NULL;
    *position+=(size_t)(end-value)+1U;
    return value;
}
int main(int argc,char **argv) {
    if(argc>1 && (strcmp(argv[1],"--process-probe")==0 || strcmp(argv[1],"--process-probe-reexec")==0))
        return sucrune_process_probe_main(argc,argv);
    if (argc!=4 || argv[0][0]!='/' || strlen(argv[0])>=sizeof(installed_runner)) return 126;
    const char *leaf=strrchr(argv[0],'/');
    if (leaf==NULL || strcmp(leaf+1,SUCRUNE_RUNNER_FILE)!=0) return 126;
    memcpy(installed_runner,argv[0],strlen(argv[0])+1U);
    if (strcmp(argv[1],SUCRUNE_GUEST_EXEC_MODE)==0) return child_guest_exec(argv[2],argv[3]);
    if(argc!=4 || strcmp(argv[1],"--sucrune-runner-v1")!=0 || strcmp(argv[2],"7")!=0) return 126;
    char *end=NULL;errno=0;long expected=strtol(argv[3],&end,10);
    if(errno!=0 || end==argv[3] || *end!='\0' || expected<=0 || expected>INT_MAX) return runner_error(ST_PROTOCOL,EINVAL);
    if(prctl(PR_SET_PDEATHSIG,SIGKILL,0UL,0UL,0UL)!=0) return runner_error(ST_PDEATH,errno);
    if(getppid()!=(pid_t)expected) return runner_error(ST_PDEATH,ESRCH);
    sigset_t empty;sigemptyset(&empty);
    if(sigprocmask(SIG_SETMASK,&empty,NULL)!=0) return runner_error(ST_PROTOCOL,errno);
    struct runner_message *packet=malloc(sizeof(*packet));
    if(packet==NULL) return runner_error(ST_PROTOCOL,ENOMEM);
    ssize_t received=receive_packet(RUNNER_CONTROL_FD,packet,sizeof(*packet));
    if(received<(ssize_t)sizeof(packet->header) || received>(ssize_t)sizeof(*packet) ||
       packet->header.magic!=RUNNER_MAGIC || packet->header.version!=RUNNER_VERSION ||
       packet->header.text_size>SUCRUNE_RUNNER_TEXT_LIMIT || packet->header.argc>RUNNER_ARG_LIMIT ||
       packet->header.envc>RUNNER_ARG_LIMIT || packet->header.has_input>1U ||
       packet->header.reserved[0]!=0U || packet->header.reserved[1]!=0U ||
       (size_t)received!=sizeof(packet->header)+packet->header.text_size) {free(packet);return runner_error(ST_PROTOCOL,EPROTO);}
    size_t position=0U;
    const char *path=take_string(packet,&position,RUNNER_PATH_LIMIT);
    const char *cwd=take_string(packet,&position,RUNNER_PATH_LIMIT);
    const char *arguments[RUNNER_ARG_LIMIT], *environment[RUNNER_ARG_LIMIT];
    int valid=path!=NULL && path[0]=='/' && cwd!=NULL;
    for(size_t i=0;i<packet->header.argc;i++) {
        arguments[i]=take_string(packet,&position,RUNNER_STRING_LIMIT+1U);if(arguments[i]==NULL) valid=0;
    }
    for(size_t i=0;i<packet->header.envc;i++) {
        environment[i]=take_string(packet,&position,RUNNER_STRING_LIMIT+1U);if(environment[i]==NULL) valid=0;
    }
    if(!valid || position!=packet->header.text_size) {free(packet);return runner_error(ST_PROTOCOL,EINVAL);}
    char report[SUCRUNE_RUNNER_REPORT_LIMIT];
    int result=sucrune_linux_run(3,path,packet->header.argc,arguments,packet->header.envc,environment,cwd,
        4,5,report,sizeof(report),packet->header.has_input ? RUNNER_INPUT_FD : -1);
    free(packet);
    size_t length=strnlen(report,sizeof(report));
    if(length==sizeof(report)) return runner_error(ST_REPORT,EOVERFLOW);
    struct runner_reply reply={.magic=RUNNER_MAGIC,.version=RUNNER_VERSION,.kind=REPLY_REPORT,
        .size=(uint32_t)length,.status=result==0 ? 0 : 1};
    if(send_parts(RUNNER_CONTROL_FD,&reply,sizeof(reply),report,length)!=(ssize_t)(sizeof(reply)+length)) return 126;
    (void)close(RUNNER_CONTROL_FD);(void)close(3);(void)close(4);(void)close(5);
    /* Host fd1/fd2 intentionally remain open until process exit. Their pipe
     * EOF is also the child-lifetime barrier when the worker parent dies.
     * Removing these aliases requires a separate confirmed child-death barrier. */
    return result==0 ? 0 : 1;
}
#endif
