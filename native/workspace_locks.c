#include "workspace_locks.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* One private Linux OFD per (guest process, inode). The kernel arbitrates
 * overlap, including external POSIX/OFD locks. The interval list records
 * guest PIDs for GETLK, since the kernel reports -1 for OFD owners. */
struct span { int64_t first, last; int16_t type; };
struct sucrune_inode_owner {
    struct sucrune_inode_owner *next, *all_next;
    dev_t dev; ino_t ino;
    int fd, pid;
    size_t count;
    struct span *spans;
};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct sucrune_inode_owner *all;
#define MAX_SPANS 4096U

static struct sucrune_inode_owner *find_owner(struct sucrune_record_locks *session, const struct stat *st) {
    for (struct sucrune_inode_owner *o=session->head; o; o=o->next)
        if (o->dev==st->st_dev && o->ino==st->st_ino) return o;
    return NULL;
}
static void remove_owner(struct sucrune_record_locks *session, struct sucrune_inode_owner *o) {
    struct sucrune_inode_owner **link=&session->head;
    while (*link!=o) link=&(*link)->next;
    *link=o->next;
    link=&all;
    while (*link!=o) link=&(*link)->all_next;
    *link=o->all_next;
    close(o->fd); free(o->spans); free(o);
}
void sucrune_record_close(struct sucrune_record_locks *session, int file) {
    /* All mutations of this session originate from its one broker thread. */
    if (!session->head) return;
    struct stat st;
    if (fstat(file,&st)!=0) return;
    pthread_mutex_lock(&lock);
    struct sucrune_inode_owner *o=find_owner(session,&st);
    if (o) remove_owner(session,o);
    pthread_mutex_unlock(&lock);
}
void sucrune_record_destroy(struct sucrune_record_locks *session) {
    pthread_mutex_lock(&lock);
    while(session->head) remove_owner(session,session->head);
    pthread_mutex_unlock(&lock);
}
static int range(int file, off_t size, const struct sucrune_record_lock *r, struct span *requested) {
    int64_t base=0, start, end;
    if (r->whence==SEEK_END) base=size;
    else if (r->whence==SEEK_CUR) {
        base=lseek(file,0,SEEK_CUR);
        if (base < 0) {
            int error = errno;
            return error > 0 ? -error : -EIO;
        }
    } else if (r->whence!=SEEK_SET) return -EINVAL;
    if (__builtin_add_overflow(base,r->start,&start)) return -EOVERFLOW;
    if (start<0) return -EINVAL;
    if (r->length<0) {
        end=start-1;
        if (__builtin_add_overflow(start,r->length,&start) || start<0) return -EINVAL;
    } else if (!r->length) end=INT64_MAX;
    else if (__builtin_add_overflow(start,r->length-1,&end)) return -EOVERFLOW;
    *requested=(struct span){start,end,r->type};
    return 0;
}
static bool overlaps(struct span a, struct span b) { return a.first<=b.last && b.first<=a.last; }
static int by_offset(const void *a, const void *b) {
    int64_t x=((const struct span *)a)->first, y=((const struct span *)b)->first;
    return (x>y)-(x<y);
}
/* Plan changes before issuing the kernel request so allocation failure cannot
 * desynchronize the kernel's locks from the guest-PID bookkeeping. */
static int replacement(const struct sucrune_inode_owner *o, struct span req, struct span **out, size_t *count) {
    struct span *next=malloc((o->count+3U)*sizeof(*next));
    if (!next) return -ENOMEM;
    size_t n=0;
    for (size_t i=0;i<o->count;i++) {
        struct span old=o->spans[i];
        if (!overlaps(old,req)) next[n++]=old;
        else {
            if (old.first<req.first) next[n++]=(struct span){old.first,req.first-1,old.type};
            if (old.last>req.last) next[n++]=(struct span){req.last+1,old.last,old.type};
        }
    }
    if (req.type!=F_UNLCK) next[n++]=req;
    qsort(next,n,sizeof(*next),by_offset);
    size_t used=0;
    for (size_t i=0;i<n;i++) {
        if (used && next[used-1].type==next[i].type && next[used-1].last==next[i].first-1)
            next[used-1].last=next[i].last;
        else next[used++]=next[i];
    }
    if (used>MAX_SPANS) {free(next);return -ENOLCK;}
    *out=next; *count=used; return 0;
}
static int private_file(int file, int access) {
    char path[64];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",file);
    int fd=open(path,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if (fd<0 && (errno==EACCES || errno==EROFS) && access!=O_RDWR)
        fd=open(path,access|O_NONBLOCK|O_CLOEXEC);
    return fd;
}
static int query(const struct sucrune_inode_owner *own,const struct stat *st,int file,
                 struct flock *fl,struct sucrune_record_lock *r) {
    if (fcntl(own ? own->fd : file,F_OFD_GETLK,fl)<0) return -errno;
    r->type=fl->l_type;
    if (fl->l_type==F_UNLCK) return 0;
    r->whence=fl->l_whence; r->start=fl->l_start; r->length=fl->l_len; r->pid=fl->l_pid;
    if (fl->l_pid!=-1) return 0;
    for (const struct sucrune_inode_owner *o=all; o; o=o->all_next) {
        if (o==own || o->dev!=st->st_dev || o->ino!=st->st_ino) continue;
        for (size_t i=0;i<o->count;i++) {
            struct span v=o->spans[i];
            if (v.type==r->type && v.first==r->start && (v.last==INT64_MAX ? 0 : v.last-v.first+1)==r->length) {
                r->pid=o->pid; return 0;
            }
        }
    }
    return 0;
}
int sucrune_record_lock_op(struct sucrune_record_locks *session,int file,int cmd,int pid,
                           struct sucrune_record_lock *r) {
    if (pid<=0 || (cmd!=F_GETLK && cmd!=F_SETLK)) return -EINVAL;
    if (r->type!=F_RDLCK && r->type!=F_WRLCK && (r->type!=F_UNLCK || cmd==F_GETLK)) return -EINVAL;
    struct stat st;
    if (fstat(file,&st)<0) return -errno;
    if (!S_ISREG(st.st_mode)) return -EOPNOTSUPP;
    int flags=fcntl(file,F_GETFL);
    if (flags<0) return -errno;
    int access=flags&O_ACCMODE;
    if ((flags&O_PATH) || (cmd==F_SETLK && ((r->type==F_RDLCK && access==O_WRONLY) ||
        (r->type==F_WRLCK && access==O_RDONLY)))) return -EBADF;
    struct span req;
    int error=range(file,st.st_size,r,&req);
    if (error) return error;
    struct flock fl={.l_type=req.type,.l_whence=SEEK_SET,.l_start=req.first,
        .l_len=req.last==INT64_MAX ? 0 : req.last-req.first+1};
    if (cmd==F_SETLK) { r->whence=SEEK_SET; r->start=fl.l_start; r->length=fl.l_len; }
    pthread_mutex_lock(&lock);
    struct sucrune_inode_owner *o=find_owner(session,&st);
    if (cmd==F_GETLK) error=query(o,&st,file,&fl,r);
    else if (o || req.type!=F_UNLCK) {
        if (!o) {
            o=calloc(1,sizeof(*o));
            if (!o) {error=-ENOMEM;goto done;}
            o->fd=private_file(file,access);
            if (o->fd<0) {error=-errno;free(o);goto done;}
            o->dev=st.st_dev; o->ino=st.st_ino; o->pid=pid;
            o->next=session->head; session->head=o;
            o->all_next=all; all=o;
        }
        struct span *next=NULL; size_t n=0;
        error=replacement(o,req,&next,&n);
        if (!error && fcntl(o->fd,F_OFD_SETLK,&fl)<0) error=-errno;
        if (!error) {free(o->spans);o->spans=next;o->count=n;}
        else free(next);
        if (!o->count) remove_owner(session,o);
    }
done:
    pthread_mutex_unlock(&lock);
    return error;
}
