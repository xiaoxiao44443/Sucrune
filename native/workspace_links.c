#include "workspace_links.h"
#include "workspace_links_recover.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PREFIX SUCRUNE_INODE_MARKER_PREFIX
#define STORE_SUFFIX ".sucrune-inodes-v1"
struct object { char id[33], marker[sizeof(PREFIX)+32], refs[39], dirty[40]; uint32_t count; };
static void names(struct object *o) {
    snprintf(o->marker,sizeof(o->marker),PREFIX "%s",o->id);
    snprintf(o->refs,sizeof(o->refs),"%s.refs",o->id);
    snprintf(o->dirty,sizeof(o->dirty),"%s.dirty",o->id);
}
static void identity(const struct stat *st,char id[33]) {
    snprintf(id,33,"%016" PRIx64 "%016" PRIx64,(uint64_t)st->st_dev,(uint64_t)st->st_ino);
}
static int store(struct sucrune_workspace_links *l,int create) {
    if(l->store>=0) return 0;
    if(create && mkdirat(l->parent,l->name,0700)!=0 && errno!=EEXIST) return -errno;
    int fd=openat(l->parent,l->name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return -errno;
    struct stat st;
    if(fstat(fd,&st)!=0 || st.st_uid!=geteuid() || (st.st_mode&0777)!=0700) {close(fd);return -EACCES;}
    l->store=fd;
    if(create && fsync(l->parent)!=0) return -errno;
    return 0;
}
int sucrune_links_init(struct sucrune_workspace_links *l,int root,const char *workspace) {
    l->parent=-1;l->store=-1;
    size_t end=strlen(workspace);
    while(end>1U && workspace[end-1U]=='/') end--;
    size_t begin=end;while(begin>0U && workspace[begin-1U]!='/') begin--;
    size_t length=end-begin;
    if(!length || length+sizeof(STORE_SUFFIX)>sizeof(l->name)) return -ENAMETOOLONG;
    memcpy(l->name,workspace+begin,length);memcpy(l->name+length,STORE_SUFFIX,sizeof(STORE_SUFFIX));
    l->parent=openat(root,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(l->parent<0) return -errno;
    if(flock(l->parent,LOCK_EX)!=0) return -errno;
    int rc=store(l,0);
    if(rc==0) rc=sucrune_links_recover(root,l->store);
    else if(rc==-ENOENT) rc=0;
    if(flock(l->parent,LOCK_UN)!=0 && rc==0) rc=-errno;
    return rc;
}
int sucrune_links_clone(struct sucrune_workspace_links *l,const struct sucrune_workspace_links *p) {
    *l=*p;l->store=-1;l->parent=openat(p->parent,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(l->parent<0) return -errno;
    if(p->store>=0 && (l->store=fcntl(p->store,F_DUPFD_CLOEXEC,3))<0) return -errno;
    return 0;
}
void sucrune_links_destroy(struct sucrune_workspace_links *l) {
    if(l->parent>=0) close(l->parent);
    if(l->store>=0) close(l->store);
    l->parent=l->store=-1;
}
/* Returns 1 only for the reserved, syntactically exact marker. */
static int marker(int parent,const char *name,struct object *o) {
    char value[sizeof(PREFIX)+33];
    ssize_t n=readlinkat(parent,name,value,sizeof(value));
    if(n<0) return errno==EINVAL || errno==ENOENT ? 0 : -errno;
    const size_t prefix=sizeof(PREFIX)-1U;
    if((size_t)n<prefix || memcmp(value,PREFIX,prefix)!=0) return 0;
    if((size_t)n!=prefix+32U) return -EUCLEAN;
    memcpy(o->id,value+prefix,32U);o->id[32]=0;
    if(strspn(o->id,"0123456789abcdef")!=32U) return -EUCLEAN;
    names(o);return 1;
}
static int checked(struct sucrune_workspace_links *l,struct object *o) {
    int rc=store(l,0);
    if(rc!=0) return rc==-ENOENT ? -EUCLEAN : rc;
    struct stat st;
    if(fstatat(l->store,o->dirty,&st,AT_SYMLINK_NOFOLLOW)==0 || errno!=ENOENT) return -EUCLEAN;
    if(fstatat(l->store,o->id,&st,AT_SYMLINK_NOFOLLOW)!=0 || !S_ISREG(st.st_mode) ||
       st.st_uid!=geteuid() || st.st_nlink!=1U) return -EUCLEAN;
    char real[33];identity(&st,real);
    if(strcmp(o->id,real)!=0) return -EUCLEAN;
    int fd=openat(l->store,o->refs,O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return -EUCLEAN;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1U ||
       (st.st_mode&077)!=0 || st.st_size!=4) {close(fd);return -EUCLEAN;}
    unsigned char data[5];
    ssize_t got=read(fd,data,sizeof(data));close(fd);
    if(got!=4) return -EUCLEAN;
    o->count=(uint32_t)data[0]|((uint32_t)data[1]<<8)|((uint32_t)data[2]<<16)|((uint32_t)data[3]<<24);
    return o->count ? 0 : -EUCLEAN;
}
static int begin(struct sucrune_workspace_links *l,struct object *o) {
    int fd=openat(l->store,o->dirty,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return errno==EEXIST ? -EUCLEAN : -errno;
    close(fd);return fsync(l->store)==0 ? 0 : -errno;
}
static int commit(struct sucrune_workspace_links *l,struct object *o,uint32_t count) {
    if(!count) {
        if(unlinkat(l->store,o->id,0)!=0 || unlinkat(l->store,o->refs,0)!=0) return -errno;
    } else {
        int fd=openat(l->store,o->refs,O_CREAT|O_WRONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0) return -errno;
        unsigned char data[4]={(unsigned char)count,(unsigned char)(count>>8),(unsigned char)(count>>16),(unsigned char)(count>>24)};
        int rc=pwrite(fd,data,4,0)==4 && ftruncate(fd,4)==0 && fsync(fd)==0 ? 0 : -EIO;
        close(fd);if(rc!=0) return rc;
    }
    if(fsync(l->store)!=0 || unlinkat(l->store,o->dirty,0)!=0 || fsync(l->store)!=0) return -errno;
    return 0;
}
int sucrune_links_open(struct sucrune_workspace_links *l,int parent,const char *name,int flags,mode_t mode) {
    if ((flags & O_CREAT) != 0) {
        /* Only chmod a newly created inode. The manager has its own umask,
         * shared with unrelated threads; its process state must not change. */
        int created=openat(parent,name,flags|O_EXCL|O_NOFOLLOW,0600);
        if (created >= 0) {
            if (fchmod(created,mode)==0) return created;
            int error=errno;
            close(created);
            (void)unlinkat(parent,name,0);
            return -error;
        }
        if (errno!=EEXIST || (flags&O_EXCL)!=0) return -errno;
        flags &= ~(O_CREAT|O_EXCL);
    }
    int fd=openat(parent,name,flags|O_NOFOLLOW);
    if(fd>=0 || errno!=ELOOP) return fd>=0 ? fd : -errno;
    struct object o;int rc=marker(parent,name,&o);
    if(rc<=0) return rc<0 ? rc : -ELOOP;
    if((flags&(O_EXCL|O_CREAT))==(O_EXCL|O_CREAT)) return -EEXIST;
    if((rc=checked(l,&o))!=0) return rc;
    fd=openat(l->store,o.id,(flags&~(O_CREAT|O_EXCL))|O_NOFOLLOW);
    return fd<0 ? -errno : fd;
}
int sucrune_links_target(struct sucrune_workspace_links *l,int fd) {
    if(fd<0) return fd;
    struct stat st;
    if(fstat(fd,&st)!=0) {int error=-errno;close(fd);return error;}
    if(!S_ISLNK(st.st_mode)) return fd;
    struct object o;int rc=marker(fd,"",&o);
    if(rc==0) return fd;
    close(fd);
    if(rc<0 || (rc=checked(l,&o))<0) return rc;
    fd=openat(l->store,o.id,O_PATH|O_NOFOLLOW|O_CLOEXEC);
    return fd<0 ? -errno : fd;
}
int sucrune_links_stat(struct sucrune_workspace_links *l,struct stat *st) {
    if(!S_ISREG(st->st_mode) || st->st_nlink==0) return 0;
    int rc=store(l,0);if(rc==-ENOENT) return 0;if(rc<0) return rc;
    struct object o;identity(st,o.id);names(&o);
    struct stat body;
    if(fstatat(l->store,o.id,&body,AT_SYMLINK_NOFOLLOW)!=0) return errno==ENOENT ? 0 : -errno;
    if((rc=checked(l,&o))!=0) return rc;
    st->st_nlink=(nlink_t)o.count;return 0;
}
static int sync_directory(int path_fd) {
    int fd=openat(path_fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return -errno;
    int rc=fsync(fd)==0 ? 0 : -errno; close(fd);return rc;
}
int sucrune_links_publish(struct sucrune_workspace_links *l,int source,const char *name,int pinned,int dest,const char *newname) {
    struct stat st,existing;
    if(fstat(pinned,&st)!=0) return -errno;
    if(!S_ISREG(st.st_mode) || st.st_uid!=geteuid()) return -EPERM;
    if(fstatat(dest,newname,&existing,AT_SYMLINK_NOFOLLOW)==0) return -EEXIST;
    if(errno!=ENOENT) return -errno;
    struct object o;
    int aliased=marker(source,name,&o);
    if(aliased<0) return aliased;
    int rc;
    if(aliased) {
        if((rc=checked(l,&o))<0) return rc;
        if(o.count==UINT32_MAX) return -EMLINK;
    } else {
        char path[64];snprintf(path,sizeof(path),"/proc/self/fd/%d",pinned);
        if(linkat(AT_FDCWD,path,dest,newname,AT_SYMLINK_FOLLOW)==0) return 0;
        if(errno!=EACCES && errno!=EPERM && errno!=EOPNOTSUPP) return -errno;
        if(st.st_nlink!=1U) return -EOPNOTSUPP;
        if(fstatat(source,name,&existing,AT_SYMLINK_NOFOLLOW)!=0) return -errno;
        if(existing.st_dev!=st.st_dev || existing.st_ino!=st.st_ino) return -ESTALE;
        identity(&st,o.id);names(&o);o.count=1;
        if((rc=store(l,1))<0) return rc;
        if(fstatat(l->store,o.id,&existing,AT_SYMLINK_NOFOLLOW)==0 || errno!=ENOENT) return -EUCLEAN;
        if(fstatat(l->store,o.refs,&existing,AT_SYMLINK_NOFOLLOW)==0 || errno!=ENOENT) return -EUCLEAN;
    }
    if((rc=begin(l,&o))<0) return rc;
    if(!aliased) {
        if(symlinkat(o.marker,l->store,o.id)!=0) return -errno;
        if(syscall(SYS_renameat2,source,name,l->store,o.id,RENAME_EXCHANGE)<0) return -errno;
        if((rc=sync_directory(source))!=0) return rc;
        if(fsync(l->store)!=0) return -errno;
    }
    if(symlinkat(o.marker,dest,newname)!=0) {
        int saved=-errno;rc=commit(l,&o,o.count);return rc<0 ? rc : saved;
    }
    if((rc=sync_directory(dest))!=0) return rc;
    return commit(l,&o,o.count+1U);
}
int sucrune_links_unlink(struct sucrune_workspace_links *l,int parent,const char *name,int flags) {
    struct object o;int managed=marker(parent,name,&o);
    if(managed<0) return managed;
    if(!managed || flags!=0) return unlinkat(parent,name,flags)==0 ? 0 : -errno;
    int rc=checked(l,&o);if(rc<0 || (rc=begin(l,&o))<0) return rc;
    if(unlinkat(parent,name,0)!=0) {int e=-errno;rc=commit(l,&o,o.count);return rc<0 ? rc : e;}
    if((rc=sync_directory(parent))!=0) return rc;
    return commit(l,&o,o.count-1U);
}
int sucrune_links_rename(struct sucrune_workspace_links *l,int parent,const char *name,int other,const char *newname) {
    struct object a,b;
    int src=marker(parent,name,&a),dst=marker(other,newname,&b),rc;
    if(src<0 || dst<0) return src<0 ? src : dst;
    if(src && (rc=checked(l,&a))<0) return rc;
    if(dst && (rc=checked(l,&b))<0) return rc;
    if(src && dst && strcmp(a.id,b.id)==0) return 0;
    if(dst && (rc=begin(l,&b))<0) return rc;
    if(renameat(parent,name,other,newname)!=0) {
        int saved=-errno;if(dst && (rc=commit(l,&b,b.count))<0) return rc;return saved;
    }
    if(!dst) return 0;
    if((rc=sync_directory(parent))!=0 || (rc=sync_directory(other))!=0) return rc;
    return commit(l,&b,b.count-1U);
}
int sucrune_links_dirents(struct sucrune_workspace_links *l,int directory,unsigned char *data,size_t length) {
    for(size_t offset=0;offset<length;) {
        unsigned char *d=data+offset;uint16_t size;
        if(length-offset<20U) return -EIO;
        memcpy(&size,d+16,2);if(size<20U || size>length-offset || !memchr(d+19,0,(size_t)size-19U)) return -EIO;
        if(d[18]==DT_LNK || d[18]==DT_UNKNOWN) {
            struct object o;int rc=marker(directory,(char *)d+19,&o);
            if(rc<0) return rc;
            if(rc) {
                if((rc=checked(l,&o))<0) return rc;
                struct stat st;if(fstatat(l->store,o.id,&st,AT_SYMLINK_NOFOLLOW)!=0) return -errno;
                uint64_t ino=(uint64_t)st.st_ino;memcpy(d,&ino,8);d[18]=DT_REG;
            }
        }
        offset+=size;
    }return 0;
}
