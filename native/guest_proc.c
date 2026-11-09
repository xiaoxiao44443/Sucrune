#include "guest_proc.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum proc_kind { PROC_ROOT, PROC_PID, PROC_STAT };
struct sucrune_proc_file {
    struct sucrune_arm64_stat metadata;
    enum proc_kind kind;
    size_t used, position;
    unsigned char bytes[4096];
};
static const char *proc_suffix(const char *path) {
    if(path==NULL || *path!='/') return NULL;
    while(*path=='/') path++;
    /* Called by the post-fork raw dispatcher as well as the primary runner. */
    if(*path++!='p' || *path++!='r' || *path++!='o' || *path++!='c' ||
       (*path!='/' && *path!='\0')) return NULL;
    while(*path=='/') path++;
    return path;
}
int sucrune_proc_path(const char *path) { return proc_suffix(path)!=NULL; }
static int parse(const char *path,int32_t self,enum proc_kind *kind,int32_t *pid) {
    const char *p=proc_suffix(path);
    if(p==NULL) return -ENOENT;
    if(*p=='\0') { *kind=PROC_ROOT; *pid=0; return 0; }
    if(p[0]=='s' && p[1]=='e' && p[2]=='l' && p[3]=='f' && (p[4]=='/' || p[4]=='\0')) { *pid=self; p+=4; }
    else {
        if(*p<'1' || *p>'9') return -ENOENT;
        int32_t value=0;
        while(*p>='0' && *p<='9') {
            int digit=*p++-'0';
            if(value>(INT32_MAX-digit)/10) return -ENOENT;
            value=value*10+digit;
        }
        *pid=value;
    }
    if(*p=='\0') { *kind=PROC_PID; return 0; }
    if(*p!='/') return -ENOENT;
    while(*p=='/') p++;
    if(*p=='\0') { *kind=PROC_PID; return 0; }
    if(*p++!='s' || *p++!='t' || *p++!='a' || *p++!='t' || *p!='\0') return -ENOENT;
    *kind=PROC_STAT; return 0;
}
int sucrune_proc_self_stat(const char *path,int32_t self) {
    enum proc_kind kind; int32_t pid;
    return parse(path,self,&kind,&pid)==0 && kind==PROC_STAT && pid==self;
}
static void metadata(struct sucrune_arm64_stat *out,const struct stat *st) {
    *out=(struct sucrune_arm64_stat){.device=st->st_dev,.inode=st->st_ino,.mode=st->st_mode,
        .nlink=(uint32_t)st->st_nlink,.uid=st->st_uid,.gid=st->st_gid,.rdevice=st->st_rdev,.size=st->st_size,
        .block_size=(int32_t)st->st_blksize,.blocks=st->st_blocks,.atime_sec=st->st_atim.tv_sec,
        .atime_nsec=(uint64_t)st->st_atim.tv_nsec,.mtime_sec=st->st_mtim.tv_sec,
        .mtime_nsec=(uint64_t)st->st_mtim.tv_nsec,.ctime_sec=st->st_ctim.tv_sec,.ctime_nsec=(uint64_t)st->st_ctim.tv_nsec};
}
static int target_metadata(struct sucrune_process_group *group,enum proc_kind kind,int32_t pid,
                           struct sucrune_arm64_stat *out) {
    struct stat st;
    if(kind==PROC_ROOT) {
        // No global /proc directory open or enumeration. Looking up the
        // mount point metadata does not depend on its read permissions.
        if(fstatat(AT_FDCWD,"/proc",&st,AT_SYMLINK_NOFOLLOW)!=0) return -errno;
    } else {
        int fd=sucrune_processes_open_proc(group,pid,kind==PROC_STAT?2:0);
        if(fd<0) return fd;
        int result=fstat(fd,&st)==0?0:-errno;
        (void)close(fd);
        if(result<0) return result;
    }
    metadata(out,&st); return 0;
}
int sucrune_proc_path_stat(struct sucrune_process_group *group,const char *path,struct sucrune_arm64_stat *out) {
    enum proc_kind kind; int32_t pid;
    int result=parse(path,(int32_t)getpid(),&kind,&pid);
    return result<0?result:target_metadata(group,kind,pid,out);
}
static int append_entry(struct sucrune_proc_file *f,uint64_t inode,const char *name,unsigned char type) {
    size_t namesize=strlen(name)+1U;
    uint16_t length=(uint16_t)((19U+namesize+7U)&~(size_t)7U);
    if(length>sizeof(f->bytes)-f->used) return -EOVERFLOW;
    unsigned char *entry=f->bytes+f->used;
    int64_t next=(int64_t)(f->used+length);
    memcpy(entry,&inode,8U); memcpy(entry+8,&next,8U); memcpy(entry+16,&length,2U);
    entry[18]=type; memcpy(entry+19,name,namesize);
    f->used+=length; return 0;
}
static int append_pid(struct sucrune_proc_file *f,struct sucrune_process_group *group,int32_t pid) {
    // Re-check under the reap lock. A child reaped after the enumeration
    // snapshot is omitted, even if its numeric PID now belongs to another app.
    int fd=sucrune_processes_open_proc(group,pid,0);
    if(fd==-ENOENT || fd==-ESRCH) return 0;
    if(fd<0) return fd;
    struct stat st;
    int result=fstat(fd,&st)==0?0:-errno;
    (void)close(fd);
    if(result<0) return result;
    char name[16];
    (void)snprintf(name,sizeof(name),"%d",(int)pid);
    return append_entry(f,st.st_ino,name,DT_DIR);
}
int sucrune_proc_filter_stat(const char *input,size_t length,unsigned char *output) {
    if(length<5U || length>=4096U || input[length-1U]!='\n') return -EIO;
    size_t after=length-1U;
    while(after>0U && input[after-1U]!=')') after--;
    if(after==0U || after+1U>=length || input[after]!=' ') return -EIO;
    size_t offset=after+1U,written=0;
    while(written<offset) { output[written]=(unsigned char)input[written]; written++; }
    unsigned int field=3;
    while(offset<length) {
        size_t start=offset;
        while(offset<length && input[offset]!=' ' && input[offset]!='\n' && input[offset]!='\0') offset++;
        if(offset==start || offset>=length || input[offset]=='\0') return -EIO;
        /* Exclude the Bionic runner's code, stack, wait-channel, argv and env addresses. */
        if((field>=26U && field<=30U) || field==35U || (field>=45U && field<=51U)) output[written++]='0';
        else for(size_t i=start;i<offset;i++) output[written++]=(unsigned char)input[i];
        output[written++]=(unsigned char)input[offset++];
        if(output[written-1U]=='\n') return field>=22U && offset==length ? (int)written : -EIO;
        field++;
    }
    return -EIO;
}
static int fill_stat(struct sucrune_proc_file *f,int fd) {
    char line[4096]; size_t used=0;
    while(used<sizeof(line)-1U) {
        ssize_t n=read(fd,line+used,sizeof(line)-1U-used);
        if(n<0 && errno==EINTR) continue;
        if(n<0) return -errno;
        if(n==0) break;
        used+=(size_t)n;
    }
    if(used==sizeof(line)-1U) return -EIO;
    int result=sucrune_proc_filter_stat(line,used,f->bytes);
    if(result>=0) f->used=(size_t)result;
    return result<0 ? result : 0;
}
int sucrune_proc_open(struct sucrune_proc_table *table,struct sucrune_process_group *group,
                      const char *path,uint64_t flags,int *handle) {
    enum proc_kind kind; int32_t pid;
    int result=parse(path,(int32_t)getpid(),&kind,&pid);
    if(result!=0) return result;
    if((flags&(O_ACCMODE|O_CREAT|O_TRUNC|O_APPEND|O_EXCL))!=0U) return -EROFS;
    if((flags&~(uint64_t)(O_CLOEXEC|O_NONBLOCK|O_DIRECTORY|O_NOFOLLOW|O_LARGEFILE))!=0U) return -EINVAL;
    if((flags&O_DIRECTORY)!=0U && kind==PROC_STAT) return -ENOTDIR;
    unsigned int slot=0U;
    while(slot<SUCRUNE_LINUX_FD_LIMIT && table->files[slot]!=NULL) slot++;
    if(slot==SUCRUNE_LINUX_FD_LIMIT) return -EMFILE;
    struct sucrune_proc_file *f=calloc(1,sizeof(*f));
    if(f==NULL) return -ENOMEM;
    f->kind=kind;
    if(kind==PROC_STAT) {
        int fd=sucrune_processes_open_proc(group,pid,1);
        if(fd<0) result=fd;
        else {
            struct stat st;
            if(fstat(fd,&st)!=0) result=-errno;
            else {metadata(&f->metadata,&st); result=fill_stat(f,fd);}
            (void)close(fd);
        }
    } else {
        result=target_metadata(group,kind,pid,&f->metadata);
        if(result==0) {
            if(kind==PROC_ROOT) {
                int32_t pids[SUCRUNE_PROCESS_LIMIT+1U];
                int count=sucrune_processes_proc_pids(group,pids,SUCRUNE_PROCESS_LIMIT+1U);
                if(count<0) result=count;
                for(int i=0;i<count && result==0;i++) result=append_pid(f,group,pids[i]);
            } else {
                struct sucrune_arm64_stat st;
                result=target_metadata(group,PROC_STAT,pid,&st);
                if(result==0) result=append_entry(f,st.inode,"stat",DT_REG);
            }
        }
    }
    if(result!=0) { free(f); return result; }
    table->files[slot]=f; *handle=-2-(int)slot; return 0;
}
int sucrune_proc_has(const struct sucrune_proc_table *table,int h) {
    return h<=-2 && h>=-1-(int)SUCRUNE_LINUX_FD_LIMIT && table->files[-2-h]!=NULL;
}
void sucrune_proc_close(struct sucrune_proc_table *table,int h) {
    if(sucrune_proc_has(table,h)) { free(table->files[-2-h]); table->files[-2-h]=NULL; }
}
int sucrune_proc_stat(struct sucrune_proc_table *table,int h,struct sucrune_arm64_stat *st) {
    if(!sucrune_proc_has(table,h)) return -EBADF;
    *st=table->files[-2-h]->metadata; return 0;
}
int64_t sucrune_proc_read(struct sucrune_proc_table *table,int h,void *out,size_t count,int directory,int64_t position) {
    if(!sucrune_proc_has(table,h)) return -EBADF;
    struct sucrune_proc_file *f=table->files[-2-h];
    if(directory && f->kind==PROC_STAT) return -ENOTDIR;
    if(!directory && f->kind!=PROC_STAT) return -EISDIR;
    size_t start=position<0?f->position:(size_t)position;
    if(start>=f->used) return 0;
    size_t transfer=f->used-start;
    if(transfer>count) transfer=count;
    if(directory) {
        size_t end=start;
        while(end<f->used) {
            uint16_t len; memcpy(&len,f->bytes+end+16U,sizeof(len));
            if((size_t)len>transfer-(end-start)) break;
            end+=len;
        }
        if(end==start) return -EINVAL;
        transfer=end-start;
    }
    if(transfer!=0U) memcpy(out,f->bytes+start,transfer);
    if(position<0) f->position+=transfer;
    return (int64_t)transfer;
}
int64_t sucrune_proc_seek(struct sucrune_proc_table *table,int h,int64_t offset,int whence) {
    if(!sucrune_proc_has(table,h)) return -EBADF;
    struct sucrune_proc_file *f=table->files[-2-h];
    if(f->kind!=PROC_STAT) {
        if(whence!=SEEK_SET || offset!=0) return -EINVAL;
        f->position=0U; return 0;
    }
    int64_t base=whence==SEEK_SET?0:whence==SEEK_CUR?(int64_t)f->position:whence==SEEK_END?(int64_t)f->used:-1;
    if(base<0 || offset< -base || offset>INT64_MAX-base) return -EINVAL;
    f->position=(size_t)(base+offset); return base+offset;
}
