#include "workspace_links_recover.h"
/* These test operations and checks must also run in a Release build. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void touch_at(int dir,const char *name) {
    int fd=openat(dir,name,O_CREAT|O_EXCL|O_WRONLY,0600);
    assert(fd>=0 && close(fd)==0);
}
static int absent(int dir,const char *name) {
    struct stat st;
    return fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
}
static unsigned references(int dir,const char *name) {
    unsigned char b[4];
    int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW);
    assert(fd>=0 && read(fd,b,sizeof(b))==4 && close(fd)==0);
    return (unsigned)b[0]|((unsigned)b[1]<<8)|((unsigned)b[2]<<16)|((unsigned)b[3]<<24);
}
int main(void) {
    const char *tmp=getenv("TMPDIR");
    char scratch[1024]; int n=snprintf(scratch,sizeof(scratch),"%s/sucrune-link-recovery-XXXXXX",tmp?tmp:"/tmp");
    assert(n>0 && (size_t)n<sizeof(scratch) && mkdtemp(scratch));
    int base=open(scratch,O_RDONLY|O_DIRECTORY);
    assert(base>=0 && mkdirat(base,"w",0700)==0 && mkdirat(base,"s",0700)==0);
    int w=openat(base,"w",O_RDONLY|O_DIRECTORY),s=openat(base,"s",O_RDONLY|O_DIRECTORY);
    assert(w>=0 && s>=0 && mkdirat(w,"dir",0700)==0);
    int sub=openat(w,"dir",O_RDONLY|O_DIRECTORY);
    int original=openat(w,"original",O_CREAT|O_EXCL|O_RDWR,0600);
    struct stat st;
    assert(sub>=0 && original>=0 && write(original,"xyz",3)==3 && fstat(original,&st)==0);
    char id[33],marker[64],dirty[48],refs[48];
    (void)snprintf(id,sizeof(id),"%016" PRIx64 "%016" PRIx64,(uint64_t)st.st_dev,(uint64_t)st.st_ino);
    (void)snprintf(marker,sizeof(marker),"sucrune:inode:v1:%s",id);
    (void)snprintf(dirty,sizeof(dirty),"%s.dirty",id);
    (void)snprintf(refs,sizeof(refs),"%s.refs",id);
    /* Before exchange: a staging symlink exists but the ordinary source is untouched. */
    touch_at(s,dirty); assert(symlinkat(marker,s,id)==0);
    assert(sucrune_links_recover(w,s)==0 && absent(s,id) && absent(s,dirty) && !absent(w,"original"));
    /* After exchange, before publishing destination or the first refs record. */
    touch_at(s,dirty);
    assert(renameat(w,"original",s,id)==0 && symlinkat(marker,w,"original")==0);
    assert(sucrune_links_recover(w,s)==0 && references(s,refs)==1);
    /* Count a second alias below a directory but never follow unrelated symlinks. */
    touch_at(s,dirty);
    assert(symlinkat(marker,sub,"dest")==0 && symlinkat("dir",w,"unrelated")==0);
    assert(sucrune_links_recover(w,s)==0 && references(s,refs)==2 && absent(s,dirty));
    touch_at(s,dirty);
    assert(unlinkat(w,"original",0)==0 && sucrune_links_recover(w,s)==0 && references(s,refs)==1);
    /* Corrupt refs is never followed, replaced or silently repaired. */
    touch_at(s,dirty);
    assert(unlinkat(s,refs,0)==0 && symlinkat("../w/unrelated",s,refs)==0);
    assert(sucrune_links_recover(w,s)==-EUCLEAN && !absent(s,dirty) && !absent(s,id));
    /* Last unlink: removing the last body name leaves the pre-existing open FD usable. */
    assert(unlinkat(s,refs,0)==0 && unlinkat(sub,"dest",0)==0);
    assert(sucrune_links_recover(w,s)==0 && absent(s,id) && absent(s,refs) && absent(s,dirty));
    char data[3]; assert(pread(original,data,3,0)==3 && memcmp(data,"xyz",3)==0);
    assert(close(original)==0 && close(sub)==0);
    assert(unlinkat(w,"dir",AT_REMOVEDIR)==0 && unlinkat(w,"unrelated",0)==0);
    assert(close(w)==0 && close(s)==0 && unlinkat(base,"w",AT_REMOVEDIR)==0 && unlinkat(base,"s",AT_REMOVEDIR)==0);
    assert(close(base)==0 && rmdir(scratch)==0);
    puts("PASS interrupted promotion, nested recount, last unlink, open inode and corrupt metadata refusal");
    return 0;
}
