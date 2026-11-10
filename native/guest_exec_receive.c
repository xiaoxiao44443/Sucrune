#include "guest_exec_receive.h"
#include "pty_broker.h"
#include "broker_transport.h"
#include "linux_elf.h"
#include "workspace_broker.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int socket_type(int fd,int expected) {
    int value=0; socklen_t n=sizeof(value);
    return getsockopt(fd,SOL_SOCKET,SO_TYPE,&value,&n)==0 && n==sizeof(value) && value==expected;
}
static int sealed_image(int fd,struct stat *st) {
    int seals=fcntl(fd,F_GET_SEALS);
    int all=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
    return seals>=0 && (seals&all)==all && fstat(fd,st)==0 && S_ISREG(st->st_mode) &&
        st->st_size>=(off_t)sizeof(Elf64_Ehdr) && st->st_size<=SUCRUNE_LINUX_MAX_FILE;
}
int sucrune_exec_read_snapshot(int fd,void **bytes,size_t *size) {
    *bytes=NULL; *size=0U;
    struct stat st;
    if (!sealed_image(fd,&st)) return ENOEXEC;
    size_t length=(size_t)st.st_size;
    unsigned char *data=malloc(length);
    if (!data) return ENOMEM;
    size_t at=0;
    while (at<length) {
        ssize_t n=pread(fd,data+at,length-at,(off_t)at);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { int error=n<0?errno:EIO; free(data); return error; }
        at+=(size_t)n;
    }
    *bytes=data; *size=length; return 0;
}
static const char *take(const struct sucrune_guest_exec *p,size_t *offset,size_t limit) {
    if (*offset>=p->text_size) return NULL;
    const char *s=(const char *)p+SUCRUNE_GUEST_EXEC_PREFIX(p->fd_limit)+*offset;
    size_t n=strnlen(s,p->text_size-*offset);
    if (n>=p->text_size-*offset || n>limit) return NULL;
    *offset+=n+1U; return s;
}
int sucrune_exec_check_packet(const struct sucrune_guest_exec *p,size_t bytes,int startup,
        const char **path,const char **argv,const char **envp) {
    if (!p || bytes<SUCRUNE_GUEST_EXEC_HEADER || p->magic!=SUCRUNE_GUEST_EXEC_MAGIC ||
        p->version!=SUCRUNE_GUEST_EXEC_VERSION || p->fd_limit!=SUCRUNE_LINUX_FD_LIMIT ||
        p->text_size>sizeof(p->text) || bytes!=SUCRUNE_GUEST_EXEC_PREFIX(p->fd_limit)+p->text_size ||
        p->argc==0U || p->argc>SUCRUNE_GUEST_EXEC_ARGS || p->envc>SUCRUNE_GUEST_EXEC_ENV ||
        p->exec_depth==0U || p->exec_depth>32U || p->linux_jit>1U || p->build_profile>1U || p->script>1U) return EPROTO;
    if ((p->scope.bus<0)!=(p->scope.lease<0) || p->scope.bus < -1 || p->scope.lease < -1) return EPROTO;
    if (p->scope.bus>=0 && (!socket_type(p->scope.bus,SOCK_SEQPACKET) || !socket_type(p->scope.lease,SOCK_SEQPACKET))) return EPROTO;
    int protected_fds[6]={startup,p->broker,p->image_fd,p->interp_fd,p->scope.bus,p->scope.lease};
    for (unsigned int i=0;i<6;i++) {
        if (i>=3 && protected_fds[i]==-1) continue;
        if (protected_fds[i]<3) return EBADF;
        for (unsigned int j=0;j<i;j++) if (protected_fds[j]==protected_fds[i]) return EPROTO;
    }
    struct stat st;
    if (!socket_type(startup,SOCK_SEQPACKET) || !socket_type(p->broker,SOCK_SEQPACKET) ||
        !sealed_image(p->image_fd,&st) || (p->interp_fd>=0 && !sealed_image(p->interp_fd,&st))) return EPROTO;
    /* Record a single socket identity per resource. Every inherited alias
     * must refer to that inode before the manager checks its canonical FD. */
    struct socket_identity { dev_t dev; ino_t ino; bool seen; };
    struct socket_identity socket_ids[SUCRUNE_LINUX_FD_LIMIT] = {0};
    for (size_t i=0;i<p->fd_limit;i++) {
        const struct sucrune_exec_fd *a=&p->entries[i];
        if (a->reserved!=0) return EPROTO;
        if (a->resource==-1) { if (a->kind!=0 || a->local_alias!=-1 || a->broker_handle!=-1 || a->network_token!=0U) return EPROTO; continue; }
        if (a->resource<0 || (unsigned int)a->resource>=p->fd_limit || a->kind<SUCRUNE_FD_INPUT ||
            a->kind>SUCRUNE_FD_LOCAL || a->pty_kind<SUCRUNE_PTY_NONE || a->pty_kind>SUCRUNE_PTY_SLAVE) return EPROTO;
        if (a->kind==SUCRUNE_FD_BROKER) {
            bool file=a->broker_handle>=(int)SUCRUNE_BROKER_HANDLE_BASE &&
                a->broker_handle<(int)(SUCRUNE_BROKER_HANDLE_BASE+p->fd_limit) && a->pty_kind==SUCRUNE_PTY_NONE;
            bool tty=sucrune_pty_slave_handle(a->broker_handle) && a->pty_kind==SUCRUNE_PTY_SLAVE && a->pty_number>=0;
            if (a->local_alias!=-1 || (!file && !tty)) return EPROTO;
        } else {
            if (a->local_alias<3 || a->broker_handle!=-1 || fcntl(a->local_alias,F_GETFD)<0) return EBADF;
            for (unsigned int j=0;j<6;j++) if (a->local_alias==protected_fds[j]) return EPROTO;
        }
        if (a->network_token!=0U) {
            if (a->kind!=SUCRUNE_FD_LOCAL || a->pty_kind!=SUCRUNE_PTY_NONE || (a->status_flags&O_NONBLOCK)==0 ||
                !sucrune_net_token_valid((int64_t)a->network_token) || fstat(a->local_alias,&st)!=0 || !S_ISSOCK(st.st_mode)) return EPROTO;
            struct socket_identity *known=&socket_ids[a->resource];
            if (known->seen && (known->dev!=st.st_dev || known->ino!=st.st_ino)) return EPROTO;
            *known=(struct socket_identity){st.st_dev,st.st_ino,true};
        }
        for (size_t j=0;j<i;j++) {
            const struct sucrune_exec_fd *b=&p->entries[j];
            if (b->resource<0) continue;
            if (a->local_alias>=0 && a->local_alias==b->local_alias) return EPROTO;
            if (b->resource==a->resource && (a->kind!=b->kind || a->broker_handle!=b->broker_handle ||
                a->status_flags!=b->status_flags || a->pty_kind!=b->pty_kind || a->pty_number!=b->pty_number ||
                a->network_token!=b->network_token)) return EPROTO;
            if (a->network_token!=0U && a->network_token==b->network_token && a->resource!=b->resource) return EPROTO;
            if (a->broker_handle>=0 && a->broker_handle==b->broker_handle && a->resource!=b->resource) return EPROTO;
        }
    }
    size_t at=0;
    *path=take(p,&at,SUCRUNE_PATH_LIMIT-1U);
    if (!*path || **path=='\0') return EINVAL;
    for (unsigned int i=0;i<p->argc;i++) if ((argv[i]=take(p,&at,SUCRUNE_GUEST_EXEC_TEXT-1U))==NULL) return EPROTO;
    if (p->script && (!argv[0][0] || strlen(argv[0]) >= SUCRUNE_PATH_LIMIT)) return EPROTO;
    for (unsigned int i=0;i<p->envc;i++) if ((envp[i]=take(p,&at,SUCRUNE_GUEST_EXEC_TEXT-1U))==NULL) return EPROTO;
    return at==p->text_size ? 0 : EPROTO;
}
int sucrune_exec_restore_fds(const struct sucrune_guest_exec *p,struct sucrune_fd_table *t,
        struct sucrune_pty_table *ptys,struct sucrune_guest_network *network) {
    // Input has already been checked. The inherited descriptors themselves are
    // stable per-entry aliases; allocate one distinct canonical FD per OFD.
    for (size_t i=0;i<p->fd_limit;i++) {
        const struct sucrune_exec_fd *a=&p->entries[i];
        if (a->resource<0) continue;
        struct sucrune_fd_resource *r=&t->resources[a->resource];
        if (a->local_alias>=0 && fcntl(a->local_alias,F_SETFD,FD_CLOEXEC)<0) return -errno;
        if (r->references==0U) {
            int handle=a->broker_handle;
            if (a->kind==SUCRUNE_FD_BROKER && a->pty_kind==SUCRUNE_PTY_SLAVE) {
                struct sucrune_request describe={.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_PTY_DESCRIBE,.args={handle}};
                struct sucrune_response reply;
                int err=sucrune_broker_exchange(p->broker,&describe,&reply,NULL,5000);
                if (err!=0 || reply.result!=a->pty_number || reply.size!=0U) return err!=0 ? err : -EPROTO;
            }
            if (a->kind!=SUCRUNE_FD_BROKER) {
                handle=fcntl(a->local_alias,F_DUPFD_CLOEXEC,16);
                if (handle<0) return -errno;
                if (a->pty_kind!=SUCRUNE_PTY_NONE) {
                    int err=sucrune_pty_adopt(ptys,handle,(enum sucrune_pty_kind)a->pty_kind,a->pty_number);
                    if (err<0) { (void)close(handle); return err; }
                }
                if (a->network_token!=0U) {
                    int err=sucrune_guest_network_restore_tcp(network,handle,a->network_token);
                    if (err<0) { (void)close(handle); return err; }
                }
            }
            r->kind=a->kind==SUCRUNE_FD_BROKER ? SUCRUNE_FD_BROKER : SUCRUNE_FD_LOCAL;
            r->handle=handle; r->status_flags=a->status_flags; t->resource_count++;
        }
        t->entries[i]=(struct sucrune_fd_entry){.resource=a->resource,.flags=0U,.host_alias=a->local_alias};
        r->references++; t->count++;
    }
    t->peak=t->count;
    return sucrune_guest_network_commit_exec(network);
}
_Noreturn void sucrune_exec_child_exit(int code,int number) {
    if (number>0 && number<NSIG) {
        struct sigaction action={.sa_handler=SIG_DFL};
        sigemptyset(&action.sa_mask);
        sigset_t unblocked; sigemptyset(&unblocked); sigaddset(&unblocked,number);
        if ((number==SIGKILL || sigaction(number,&action,NULL)==0) &&
            sigprocmask(SIG_UNBLOCK,&unblocked,NULL)==0) (void)raise(number);
        _exit(126); // Never report a failed signal delivery as signaled.
    }
    _exit(code & 255);
}
