#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <jni.h>
#endif

#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
#endif
#ifndef TIOCGPTLCK
#define TIOCGPTLCK _IOR('T', 0x39, int)
#endif

/* All descriptors are fresh, private to this measurement or borrowed from a
 * Binder PFD. No host command is executed. -1 errno fields mean unattempted.
 * Returned pairs retain O_NONBLOCK and FD_CLOEXEC on both descriptions. */
struct pty_pair {
    int master, slave, number, open_error, number_error, lock_before, lock_after;
    int unlock_error, peer_error, path_error, same_device, raw_error, window_error;
};

static int pty_prepare(struct pty_pair *p) {
    *p=(struct pty_pair){.master=-1,.slave=-1,.number=-1,.open_error=-1,.number_error=-1,
        .lock_before=-1,.lock_after=-1,.unlock_error=-1,.peer_error=-1,.path_error=-1,
        .same_device=-1,.raw_error=-1,.window_error=-1};
    const int flags=O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK;
    p->master=open("/dev/ptmx",flags);
    if (p->master<0) return p->open_error=errno;
    p->open_error=0;
    if (ioctl(p->master,TIOCGPTN,&p->number)<0) return p->number_error=errno;
    p->number_error=0;
    int lock=-1;
    if (ioctl(p->master,TIOCGPTLCK,&lock)==0) p->lock_before=lock;
    int unlock=0;
    if (ioctl(p->master,TIOCSPTLCK,&unlock)<0) return p->unlock_error=errno;
    p->unlock_error=0;
    if (ioctl(p->master,TIOCGPTLCK,&lock)==0) p->lock_after=lock;
    int peer=ioctl(p->master,TIOCGPTPEER,flags);
    p->peer_error=peer<0 ? errno : 0;
    char name[64];
    int n=snprintf(name,sizeof(name),"/dev/pts/%d",p->number);
    if (n<=0 || (size_t)n>=sizeof(name) || p->number<0) {
        if (peer>=0) (void)close(peer);
        return EOVERFLOW;
    }
    int by_name=open(name,flags|O_NOFOLLOW);
    p->path_error=by_name<0 ? errno : 0;
    if (peer>=0 && by_name>=0) {
        struct stat a,b;
        int same=fstat(peer,&a)==0 && fstat(by_name,&b)==0 && S_ISCHR(a.st_mode) &&
            S_ISCHR(b.st_mode) && a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_rdev==b.st_rdev;
        p->same_device=same;
        (void)close(by_name);
        if (!same) { (void)close(peer); return EIO; }
        p->slave=peer;
    } else p->slave=peer>=0 ? peer : by_name;
    if (p->slave<0) return p->path_error;
    struct termios term;
    if (tcgetattr(p->slave,&term)<0) return p->raw_error=errno;
    cfmakeraw(&term);
    if (tcsetattr(p->slave,TCSANOW,&term)<0 || tcgetattr(p->slave,&term)<0) return p->raw_error=errno;
    if ((term.c_lflag&(ICANON|ECHO))!=0) return p->raw_error=EIO;
    p->raw_error=0;
    struct winsize win={.ws_row=24,.ws_col=80};
    if (ioctl(p->master,TIOCSWINSZ,&win)<0) return p->window_error=errno;
    p->window_error=0;
    return 0;
}

static int pty_close_pair(struct pty_pair *p) {
    int err=0;
    if (p->slave>=0 && close(p->slave)<0) err=errno;
    if (p->master>=0 && close(p->master)<0 && err==0) err=errno;
    p->slave=-1; p->master=-1;
    return err;
}

static int64_t pty_now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)<0) return -1;
    return (int64_t)t.tv_sec*1000+(int64_t)t.tv_nsec/1000000;
}

static int pty_transfer(int fd,void *data,size_t length,int writing,int timeout) {
    int64_t start=pty_now_ms();
    if (start<0) return EIO;
    size_t done=0;
    while (done<length) {
        int64_t now=pty_now_ms();
        if (now<0) return EIO;
        int64_t remaining=start+timeout-now;
        if (remaining<=0) return ETIMEDOUT;
        struct pollfd p={.fd=fd,.events=writing ? POLLOUT : POLLIN};
        int r=poll(&p,1,(int)remaining);
        if (r==0) return ETIMEDOUT;
        if (r<0) { if (errno==EINTR) continue; return errno; }
        unsigned char *at=(unsigned char *)data+done;
        ssize_t count=writing ? write(fd,at,length-done) : read(fd,at,length-done);
        if (count==0) return EPIPE;
        if (count<0) { if (errno==EINTR || errno==EAGAIN) continue; return errno; }
        done+=(size_t)count;
    }
    return 0;
}

struct endpoint_result { int ok, error, raw, rows, cols, fd_cloexec, nonblock; const char *stage; };
static struct endpoint_result pty_endpoint(int fd,int mode,uint32_t nonce) {
    struct endpoint_result r={.ok=0,.error=0,.raw=0,.rows=-1,.cols=-1,.fd_cloexec=-1,.nonblock=-1,.stage="flags"};
    int fd_flags=fcntl(fd,F_GETFD), status=fcntl(fd,F_GETFL);
    if (fd_flags<0 || status<0) { r.error=errno; return r; }
    r.fd_cloexec=(fd_flags&FD_CLOEXEC)!=0; r.nonblock=(status&O_NONBLOCK)!=0;
    if (!r.nonblock) { r.error=EINVAL; return r; }
    r.stage="get_termios";
    struct termios term;
    if (tcgetattr(fd,&term)<0) { r.error=errno; return r; }
    r.raw=(term.c_lflag&(ICANON|ECHO))==0;
    if (!r.raw) { r.error=EIO; return r; }
    struct winsize w={0};
    r.stage="get_window";
    if (ioctl(fd,TIOCGWINSZ,&w)<0) { r.error=errno; return r; }
    r.rows=(int)w.ws_row; r.cols=(int)w.ws_col;
    if (r.rows!=(mode==2 ? 37 : 24) || r.cols!=(mode==2 ? 113 : 80)) { r.error=EPROTO; return r; }
    unsigned char ping[8]={0,0xff,0x0a,0x0d},pong[8]={0x7f,0x0d,0,0xfe},seen[8]={0};
    for (unsigned i=0;i<4U;i++) {
        ping[4U+i]=(unsigned char)(nonce>>(i*8U));
        pong[4U+i]=(unsigned char)((nonce^UINT32_C(0xb74a31c2))>>(i*8U));
    }
    if (mode!=0) {
        r.stage="read";
        r.error=pty_transfer(fd,seen,sizeof(seen),0,1200);
        if (r.error!=0) return r;
        r.stage="compare";
        if (memcmp(seen,mode==2 ? pong : ping,sizeof(seen))!=0) { r.error=EBADMSG; return r; }
    }
    if (mode==1) {
        r.stage="set_window"; w.ws_row=37; w.ws_col=113;
        if (ioctl(fd,TIOCSWINSZ,&w)<0) { r.error=errno; return r; }
    }
    if (mode!=2) {
        r.stage="write"; r.error=pty_transfer(fd,mode==0 ? ping : pong,sizeof(ping),1,1200);
        if (r.error!=0) return r;
    }
    r.ok=1; r.stage="completed";
    return r;
}

struct ctty_result {
    int child, waited, error, session_error, acquire_error, sid_error, pgrp_error, set_pgrp_error, tty_error;
    int session_matches, group_matches, ok, alias_exchange_error, alias_verified;
};
static struct ctty_result pty_controlling(int terminal,int exchange,uint32_t nonce) {
    struct ctty_result r={.child=-1,.session_error=-1,.acquire_error=-1,.sid_error=-1,.pgrp_error=-1,.set_pgrp_error=-1,.tty_error=-1,.alias_exchange_error=-1};
    int channel[2];
    if (pipe2(channel,O_CLOEXEC|O_NONBLOCK)<0) { r.error=errno; return r; }
    sigset_t all,oldmask; (void)sigfillset(&all);
    if (sigprocmask(SIG_SETMASK,&all,&oldmask)<0) { r.error=errno; (void)close(channel[0]); (void)close(channel[1]); return r; }
    pid_t pid=fork(); int fork_error=errno;
    if (pid==0) {
        (void)close(channel[0]);
        r.child=(int)getpid();
        pid_t sid=setsid(); r.session_error=sid<0 ? errno : 0;
        if (sid>=0) {
            r.acquire_error=ioctl(terminal,TIOCSCTTY,0)<0 ? errno : 0;
            if (r.acquire_error==0) {
                pid_t actual_sid=0, pg=0;
                r.sid_error=ioctl(terminal,TIOCGSID,&actual_sid)<0 ? errno : 0;
                r.session_matches=r.sid_error==0 && actual_sid==sid;
                r.pgrp_error=ioctl(terminal,TIOCGPGRP,&pg)<0 ? errno : 0;
                r.group_matches=r.pgrp_error==0 && pg==sid;
                r.set_pgrp_error=ioctl(terminal,TIOCSPGRP,&sid)<0 ? errno : 0;
                int ctl=open("/dev/tty",O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                r.tty_error=ctl<0 ? errno : 0;
                if (ctl>=0) {
                    if (exchange) {
                        struct endpoint_result result=pty_endpoint(ctl,1,nonce);
                        r.alias_exchange_error=result.error;
                        r.alias_verified=result.ok;
                    }
                    (void)close(ctl);
                }
                r.ok=r.session_matches && r.group_matches && r.set_pgrp_error==0 && r.tty_error==0;
            }
        }
        ssize_t sent=write(channel[1],&r,sizeof(r));
        _exit(sent==(ssize_t)sizeof(r) ? 0 : 2);
    }
    int restore=sigprocmask(SIG_SETMASK,&oldmask,NULL)<0 ? errno : 0;
    (void)close(channel[1]);
    if (pid<0) { r.error=fork_error; (void)close(channel[0]); return r; }
    struct ctty_result reply=r;
    int read_error=pty_transfer(channel[0],&reply,sizeof(reply),0,1800);
    (void)close(channel[0]);
    if (read_error!=0) (void)kill(pid,SIGKILL);
    int status=0; pid_t done;
    do { done=waitpid(pid,&status,0); } while (done<0 && errno==EINTR);
    if (read_error==0 && reply.child==(int)pid) r=reply;
    else r.error=read_error!=0 ? read_error : EPROTO;
    r.child=(int)pid; r.waited=done==pid;
    if (!r.waited && r.error==0) r.error=errno;
    if (r.waited && r.error==0 && (!WIFEXITED(status) || WEXITSTATUS(status)!=0)) r.error=ECHILD;
    if (restore!=0) r.error=restore;
    if (r.error!=0) r.ok=0;
    return r;
}

static void pty_ctty_json(char *out,size_t cap,struct ctty_result r) {
    (void)snprintf(out,cap,"{\"ok\":%s,\"child_pid\":%d,\"waited\":%s,\"error\":%d,\"setsid_errno\":%d,"
        "\"tiocsctty_errno\":%d,\"tiocgsid_errno\":%d,\"tiocgpgrp_errno\":%d,\"tiocspgrp_errno\":%d,"
        "\"open_dev_tty_errno\":%d,\"session_matches\":%s,\"group_matches\":%s,\"alias_exchange_errno\":%d,\"alias_verified\":%s}",
        r.ok?"true":"false",r.child,r.waited?"true":"false",r.error,r.session_error,r.acquire_error,r.sid_error,
        r.pgrp_error,r.set_pgrp_error,r.tty_error,r.session_matches?"true":"false",r.group_matches?"true":"false",
        r.alias_exchange_error,r.alias_verified?"true":"false");
}
static void pty_ep_json(char *out,size_t cap,struct endpoint_result r) {
    (void)snprintf(out,cap,"{\"ok\":%s,\"stage\":\"%s\",\"errno\":%d,\"raw\":%s,\"rows\":%d,\"columns\":%d,\"cloexec\":%d,\"nonblock\":%d}",
        r.ok?"true":"false",r.stage,r.error,r.raw?"true":"false",r.rows,r.cols,r.fd_cloexec,r.nonblock);
}
static void pty_direct_json(char *out,size_t cap) {
    struct pty_pair p;
    int err=pty_prepare(&p), verified=0;
    char ctty[500]="null", ep[300]="null";
    if (err==0) {
        struct endpoint_result a=pty_endpoint(p.master,0,UINT32_C(0xab19ef10));
        if (a.ok) a=pty_endpoint(p.slave,1,UINT32_C(0xab19ef10));
        if (a.ok) a=pty_endpoint(p.master,2,UINT32_C(0xab19ef10));
        verified=a.ok; pty_ep_json(ep,sizeof(ep),a);
        pty_ctty_json(ctty,sizeof(ctty),pty_controlling(p.slave,0,0));
    }
    int close_error=pty_close_pair(&p);
    (void)snprintf(out,cap,"{\"uid\":%d,\"pid\":%d,\"prepare_errno\":%d,\"open_ptmx_errno\":%d,\"getptn_errno\":%d,"
        "\"lock_before\":%d,\"lock_after\":%d,\"unlock_errno\":%d,\"getptpeer_errno\":%d,\"open_pts_path_errno\":%d,"
        "\"same_slave_device\":%d,\"raw_errno\":%d,\"initial_winsize_errno\":%d,\"exchange_verified\":%s,"
        "\"endpoint\":%s,\"controlling\":%s,\"close_errno\":%d}",
        (int)getuid(),(int)getpid(),err,p.open_error,p.number_error,p.lock_before,p.lock_after,p.unlock_error,p.peer_error,
        p.path_error,p.same_device,p.raw_error,p.window_error,verified?"true":"false",ep,ctty,close_error);
}

#if defined(__ANDROID__) && !defined(SUCRUNE_PTY_STANDALONE)
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_PtyNative_direct(JNIEnv *env,jclass type) {
    (void)type; char report[1600]; pty_direct_json(report,sizeof(report)); return (*env)->NewStringUTF(env,report);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_PtyNative_openPair(JNIEnv *env,jclass type) {
    (void)type; struct pty_pair p; int err=pty_prepare(&p);
    if (err!=0) (void)pty_close_pair(&p);
    jint values[3]={(jint)err,(jint)p.master,(jint)p.slave};
    jintArray array=(*env)->NewIntArray(env,3);
    if (array!=NULL) (*env)->SetIntArrayRegion(env,array,0,3,values);
    if (array==NULL || (*env)->ExceptionCheck(env)) (void)pty_close_pair(&p);
    return array;
}
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_PtyNative_endpoint(JNIEnv *env,jclass type,jint fd,jint mode,jint nonce) {
    (void)type; char report[300];
    if (mode<0 || mode>2 || fd<0) return (*env)->NewStringUTF(env,"{\"ok\":false,\"stage\":\"arguments\",\"errno\":22}");
    pty_ep_json(report,sizeof(report),pty_endpoint(fd,mode,(uint32_t)nonce));
    return (*env)->NewStringUTF(env,report);
}
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_PtyNative_controlling(JNIEnv *env,jclass type,jint fd) {
    (void)type; char report[500]; pty_ctty_json(report,sizeof(report),pty_controlling(fd,0,0)); return (*env)->NewStringUTF(env,report);
}
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_PtyNative_masterControlling(JNIEnv *env,jclass type,jint fd,jint nonce) {
    (void)type; char report[500]; pty_ctty_json(report,sizeof(report),pty_controlling(fd,1,(uint32_t)nonce)); return (*env)->NewStringUTF(env,report);
}
JNIEXPORT jint JNICALL Java_com_sucrune_probe_PtyNative_sendRight(JNIEnv *env,jclass type,jint socket_fd,jint fd) {
    (void)env; (void)type;
    unsigned char marker=0x5c;
    struct iovec iov={.iov_base=&marker,.iov_len=1};
    union {struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))];} control={0};
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
    int descriptor=fd; memcpy(CMSG_DATA(c),&descriptor,sizeof(descriptor));
    ssize_t count=sendmsg(socket_fd,&msg,MSG_NOSIGNAL|MSG_DONTWAIT);
    return count==1 ? 0 : count<0 ? errno : EIO;
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_PtyNative_receiveRight(JNIEnv *env,jclass type,jint socket_fd) {
    (void)type;
    unsigned char marker=0;
    struct iovec iov={.iov_base=&marker,.iov_len=1};
    union {struct cmsghdr align; unsigned char bytes[CMSG_SPACE(4U*sizeof(int))];} control={0};
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    ssize_t count=recvmsg(socket_fd,&msg,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
    int error=count<0 ? errno : 0, received=-1, rights=0;
    if (count>=0) {
        for (struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c!=NULL;c=CMSG_NXTHDR(&msg,c)) {
            if (c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS || c->cmsg_len<CMSG_LEN(0)) { error=EPROTO; continue; }
            size_t bytes=c->cmsg_len-CMSG_LEN(0);
            if (bytes%sizeof(int)!=0U) error=EPROTO;
            for (size_t at=0;at+sizeof(int)<=bytes;at+=sizeof(int)) {
                int descriptor; memcpy(&descriptor,(unsigned char *)CMSG_DATA(c)+at,sizeof(descriptor)); rights++;
                if (received<0) received=descriptor; else (void)close(descriptor);
            }
        }
        if (count!=1 || marker!=0x5c || (msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0 || rights!=1) error=EPROTO;
    }
    if (error && received>=0) { (void)close(received); received=-1; }
    jint values[5]={(jint)error,(jint)msg.msg_flags,(jint)rights,(jint)received,(jint)count};
    jintArray array=(*env)->NewIntArray(env,5);
    if (array!=NULL) (*env)->SetIntArrayRegion(env,array,0,5,values);
    if ((array==NULL || (*env)->ExceptionCheck(env)) && received>=0) (void)close(received);
    return array;
}
#elif defined(SUCRUNE_PTY_STANDALONE)
int main(void) {
    char report[1600]; pty_direct_json(report,sizeof(report)); (void)puts(report);
    return strstr(report,"\"exchange_verified\":true")!=NULL && strstr(report,"\"controlling\":{\"ok\":true")!=NULL ? 0 : 1;
}
#endif
