#include "workspace_links_recover.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MARKER_PREFIX "sucrune:inode:v1:"
/* Bounds apply to recovery only. A clean store never requires a workspace walk. */
#define LIMIT_ENTRIES 1000000U
#define LIMIT_DEPTH 128U
#define LIMIT_DIRTY 128U
struct dirty_id { char id[33]; uint32_t names; };
struct census {
    struct dirty_id ids[LIMIT_DIRTY];
    size_t count;
    unsigned seen;
    dev_t device;
};
static int valid_id(const char *s) {
    return strlen(s) == 32U && strspn(s, "0123456789abcdef") == 32U;
}
static int dot(const char *s) { return !strcmp(s,".") || !strcmp(s,".."); }
static DIR *independent_dir(int fd) {
    int own = openat(fd,".",O_DIRECTORY|O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (own < 0) return NULL;
    DIR *d = fdopendir(own);
    if (!d) { int err=errno; (void)close(own); errno=err; }
    return d;
}
static int marker_at(int parent,const char *name,char id[33]) {
    char value[sizeof(MARKER_PREFIX)+33U];
    const size_t prefix=sizeof(MARKER_PREFIX)-1U;
    ssize_t length=readlinkat(parent,name,value,sizeof(value)-1U);
    if (length<0) return -errno;
    value[(size_t)length]=0;
    if (strncmp(value,MARKER_PREFIX,prefix)!=0) return 0;
    if (!valid_id(value+prefix)) return -EUCLEAN;
    memcpy(id,value+prefix,33U); return 1;
}
static int scan_workspace(struct census *c,int fd,unsigned depth) {
    if (depth>LIMIT_DEPTH) return -E2BIG;
    DIR *d=independent_dir(fd);
    if (!d) return -errno;
    int rc=0;
    for (;;) {
        errno=0;
        struct dirent *entry=readdir(d);
        if (!entry) { if(errno!=0) rc=-errno; break; }
        if (dot(entry->d_name)) continue;
        if (++c->seen>LIMIT_ENTRIES) { rc=-E2BIG; break; }
        unsigned type=entry->d_type;
        if (type==DT_UNKNOWN) {
            struct stat st;
            if (fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)!=0) { rc=-errno; break; }
            type=S_ISDIR(st.st_mode)?DT_DIR:(S_ISLNK(st.st_mode)?DT_LNK:DT_REG);
        }
        if (type==DT_DIR) {
            int child=openat(fd,entry->d_name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
            if (child<0) { rc=-errno; break; }
            struct stat st;
            if (fstat(child,&st)!=0) rc=-errno;
            else if (st.st_dev!=c->device) rc=-EXDEV;
            else rc=scan_workspace(c,child,depth+1U);
            (void)close(child);
            if (rc<0) break;
        } else if (type==DT_LNK) {
            char id[33];
            rc=marker_at(fd,entry->d_name,id);
            if (rc<0) break;
            if (rc==1) for (size_t i=0;i<c->count;i++) {
                if (!strcmp(id,c->ids[i].id)) { c->ids[i].names++; break; }
            }
            rc=0;
        }
    }
    /* Reach durability for even an unlink that crashed before fsync(parent). */
    if (rc==0 && fsync(fd)!=0) rc=-errno;
    (void)closedir(d); return rc;
}
/* Verify all named objects before performing any repair. Never follow metadata symlinks. */
static int validate_body(int store,const struct dirty_id *e) {
    struct stat st;
    if (fstatat(store,e->id,&st,AT_SYMLINK_NOFOLLOW)!=0)
        return errno==ENOENT && !e->names ? 0 : -EUCLEAN;
    if (st.st_uid!=geteuid() || st.st_nlink!=1) return -EUCLEAN;
    if (S_ISREG(st.st_mode)) {
        char actual[33];
        (void)snprintf(actual,sizeof(actual),"%016" PRIx64 "%016" PRIx64,(uint64_t)st.st_dev,(uint64_t)st.st_ino);
        return strcmp(actual,e->id)==0 ? 0 : -EUCLEAN;
    }
    if (S_ISLNK(st.st_mode) && !e->names) {
        char id[33];
        return marker_at(store,e->id,id)==1 && !strcmp(e->id,id) ? 0 : -EUCLEAN;
    }
    return -EUCLEAN;
}
static int private_file(int store,const char *name,off_t max_size,int missing_ok) {
    struct stat st;
    if (fstatat(store,name,&st,AT_SYMLINK_NOFOLLOW)!=0) return errno==ENOENT && missing_ok ? 0 : -EUCLEAN;
    return S_ISREG(st.st_mode) && st.st_uid==geteuid() && st.st_nlink==1 &&
        (st.st_mode&077)==0 && st.st_size>=0 && st.st_size<=max_size ? 0 : -EUCLEAN;
}
static int unlink_optional(int dir,const char *name) {
    return unlinkat(dir,name,0)==0 || errno==ENOENT ? 0 : -errno;
}
static int repair(int store,const struct dirty_id *e) {
    char refs[38],dirty[39];
    (void)snprintf(refs,sizeof(refs),"%s.refs",e->id);
    (void)snprintf(dirty,sizeof(dirty),"%s.dirty",e->id);
    int rc=0;
    if (e->names==0) {
        rc=unlink_optional(store,e->id);
        if (rc==0) rc=unlink_optional(store,refs);
    } else {
        int fd=openat(store,refs,O_WRONLY|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
        if (fd<0) return -errno;
        unsigned char bytes[4]={(unsigned char)e->names,(unsigned char)(e->names>>8),
            (unsigned char)(e->names>>16),(unsigned char)(e->names>>24)};
        size_t pos=0;
        while(pos<sizeof(bytes)) {
            ssize_t n=pwrite(fd,bytes+pos,sizeof(bytes)-pos,(off_t)pos);
            if (n<0 && errno==EINTR) continue;
            if (n<=0) { rc=n==0?-EIO:-errno; break; }
            pos+=(size_t)n;
        }
        if (rc==0 && (ftruncate(fd,4)!=0 || fsync(fd)!=0)) rc=-errno;
        if (close(fd)!=0 && rc==0) rc=-errno;
    }
    if (rc==0 && (fsync(store)!=0 || unlinkat(store,dirty,0)!=0 || fsync(store)!=0)) rc=-errno;
    return rc;
}
int sucrune_links_recover(int root,int store) {
    DIR *d=independent_dir(store);
    if (!d) return -errno;
    struct census c={0};
    unsigned entries=0;
    int rc=0;
    for (;;) {
        errno=0;
        struct dirent *e=readdir(d);
        if (!e) { if (errno!=0) rc=-errno; break; }
        if (dot(e->d_name)) continue;
        if (++entries>LIMIT_ENTRIES) { rc=-E2BIG; break; }
        size_t len=strlen(e->d_name);
        if (len<6U || strcmp(e->d_name+len-6U,".dirty")!=0) continue;
        if (len!=38U || c.count>=LIMIT_DIRTY) { rc=-EUCLEAN; break; }
        struct dirty_id *id=&c.ids[c.count++];
        memcpy(id->id,e->d_name,32U);
        if (!valid_id(id->id) || private_file(store,e->d_name,0,0)<0) { rc=-EUCLEAN; break; }
    }
    (void)closedir(d);
    if (rc<0 || !c.count) return rc;
    struct stat root_stat;
    if (fstat(root,&root_stat)!=0) return -errno;
    c.device=root_stat.st_dev;
    if ((rc=scan_workspace(&c,root,0))<0) return rc;
    for (size_t i=0;i<c.count;i++) {
        char refs[38];
        (void)snprintf(refs,sizeof(refs),"%s.refs",c.ids[i].id);
        if ((rc=validate_body(store,&c.ids[i]))<0 || (rc=private_file(store,refs,4,1))<0) return rc;
    }
    for (size_t i=0;i<c.count;i++) if ((rc=repair(store,&c.ids[i]))<0) return rc;
    return 0;
}
