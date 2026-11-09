/* Optional host directory at /workspace. Only directory metadata and open-description
 * state live here. Files use the original descriptors supplied by the directory owner. */
static int mount_stat(struct broker *b,const char *path,struct stat *st) {
    memset(st,0,sizeof(*st));
    int rc=b->family->mount.stat(b->family->mount.context,path,st);
    if (rc<0) return rc;
    if (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode)) return -EOPNOTSUPP;
    /* Document providers need not publish a persistent inode. This path identity is
     * for stat/readdir only. Landlock anchors use the separate pinned mount root. */
    uint64_t number=UINT64_C(14695981039346656037);
    for (const unsigned char *c=(const unsigned char *)path; *c; ++c) number=(number^*c)*UINT64_C(1099511628211);
    if (!st->st_ino) {
        st->st_ino=(ino_t)(number ? number : 1);
        st->st_dev=(dev_t)0x534146;
    }
    st->st_uid=geteuid(); st->st_gid=getegid(); st->st_nlink=1; st->st_blksize=4096;
    st->st_atim=st->st_ctim=st->st_mtim;
    return 0;
}
static int pin_directory(struct broker *b,const char *path) {
    if (!*path) {
        int copy=fcntl(b->family->mount_anchor,F_DUPFD_CLOEXEC,3);
        return copy<0 ? -errno : copy;
    }
    int fd=b->family->mount.open(b->family->mount.context,path,O_RDONLY|O_DIRECTORY,0);
    if (fd<0) return fd;
    struct stat st;
    if (fstat(fd,&st)<0 || !S_ISDIR(st.st_mode)) { close(fd); return -EOPNOTSUPP; }
    return fd;
}
/* Pinning a provider directory is only an identity check. All access to its
 * children still goes through the grant, even when raw openat is filtered. */
static int same_mounted_directory(struct broker *b,int pinned,const char *path) {
    if (!*path) return 0;
    int current=pin_directory(b,path);
    if (current<0) return current;
    int result=same_inode(pinned,current);
    close(current);
    return result>0 ? 0 : result<0 ? result : -ESTALE;
}
static int mount_right(struct broker *b,unsigned int rights) {
    return ll_check(&b->domain,b->root,b->family->mount_anchor,LL_NO_TARGET,rights);
}
/* Resolve components in the granted tree. Absolute guest symlinks leading to
 * this mount have already been followed by walk_parent. Its '..' boundary is
 * the guest /; a document ID or a host path is never parsed as a guest path. */
static int walk_mount(struct broker *b,const char *start,const char *pending,bool follow,
                      bool mutation,char *leaf,bool *trailing) {
    size_t used=strlen(start);
    if (used >= sizeof(b->mount_path)) return -ENAMETOOLONG;
    memcpy(b->mount_path,start,used+1);
    b->mount_dot=false;
    b->mount_requires_dir=true;
    const char *p=pending;
    while (*p) {
        while (*p=='/') ++p;
        if (!*p) break;
        const char *end=p;
        while (*end && *end!='/') ++end;
        size_t len=(size_t)(end-p);
        if (len>255 || memchr(p,'\\',len)) return len>255 ? -ENAMETOOLONG : -EINVAL;
        struct stat parent;
        int rc=mount_stat(b,b->mount_path,&parent);
        if (rc<0 || !S_ISDIR(parent.st_mode)) return rc<0 ? rc : -ENOTDIR;
        b->mount_dot=(len==1 && *p=='.') || (len==2 && !memcmp(p,"..",2));
        b->mount_requires_dir=b->mount_dot || *end=='/';
        if (len==2 && !memcmp(p,"..",2)) {
            if (!used) {
                if (b->walk_depth>=24) return -ELOOP;
                ++b->walk_depth;
                int fd=walk_parent(b,AT_FDCWD,*end?end:"/",follow,mutation,leaf,trailing);
                --b->walk_depth;
                return fd;
            }
            while (used && b->mount_path[used-1]!='/') --used;
            if (used) --used;
            b->mount_path[used]='\0';
        } else if (!b->mount_dot) {
            if (used+!!used+len >= sizeof(b->mount_path)) return -ENAMETOOLONG;
            if (used) b->mount_path[used++]='/';
            memcpy(b->mount_path+used,p,len);
            used+=len;
            b->mount_path[used]='\0';
        }
        p=end;
    }
    *trailing=b->mount_requires_dir;
    return MOUNT_TARGET;
}
static int mount_open(struct broker *b,const struct sucrune_request *r,int *send_fd) {
    const bool exec=r->operation==SUCRUNE_BROKER_OPEN_EXEC;
    const int allowed=O_PATH|O_ACCMODE|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_LARGEFILE|O_NONBLOCK;
    if (r->args[1]<0 || r->args[1]>INT32_MAX || (r->args[1]&~(int64_t)allowed)) return -EINVAL;
    int flags=(int)r->args[1], access=flags&O_ACCMODE;
    if (access==O_ACCMODE) return -EINVAL;
    bool path_only=(flags&O_PATH)!=0;
    struct stat st;
    int rc=mount_stat(b,b->mount_path,&st);
    bool exists=rc==0;
    if (!exists && (rc!=-ENOENT || !(flags&O_CREAT) || path_only)) return rc;
    if (!exists && ((flags&O_DIRECTORY)||b->mount_requires_dir)) return -ENOENT;
    if (exists && (flags&O_CREAT) && (flags&O_EXCL) && !path_only) return -EEXIST;
    bool directory=exists && S_ISDIR(st.st_mode);
    if (!directory && ((flags&O_DIRECTORY)||b->mount_requires_dir)) return -ENOTDIR;
    if (!path_only) {
        bool writing=access!=O_RDONLY || (flags&(O_CREAT|O_TRUNC));
        if (writing && b->write_scope==SUCRUNE_WRITE_READ_ONLY) return -EACCES;
        if (directory && writing) return -EISDIR;
        unsigned int rights=directory ? LL_READ_DIR : access==O_RDONLY ? LL_READ_FILE :
            access==O_WRONLY ? LL_WRITE_FILE : LL_READ_FILE|LL_WRITE_FILE;
        if (exec) rights|=LL_EXECUTE;
        if (flags&O_TRUNC) rights|=LL_TRUNCATE;
        if (!exists) rights|=LL_MAKE_REG;
        rc=mount_right(b,rights);
        if (rc<0) return rc;
        if (exec && (directory || !(st.st_mode&0111))) return -EACCES;
        // A concurrently removed file must not turn an authorized existing-file
        // open into a creation in a domain that lacks MAKE_REG.
        if ((flags&O_CREAT) && exists && mount_right(b,LL_MAKE_REG)<0) flags&=~O_CREAT;
    }
    int slot=free_slot(b);
    if (slot<0) return slot;
    struct file_status *state=calloc(1,sizeof(*state));
    if (!state) return -ENOMEM;
    rc=pthread_mutex_init(&state->lock,NULL);
    if (rc) { free(state); return -rc; }
    atomic_init(&state->refs,1U);
    struct mount_file *m=calloc(1,sizeof(*m));
    state->mounted=m;
    if (!m || !(m->path=strdup(b->mount_path))) { release_status(state); return -ENOMEM; }
    m->path_only=path_only;
    int file;
    if (directory) file=pin_directory(b,m->path);
    else if (path_only) {
        file=openat(b->family->mount_anchor,".",O_PATH|O_CLOEXEC|O_DIRECTORY);
        if (file<0) file=-errno;
    } else {
        mode_t mode=r->args[3]==1 ? ((mode_t)r->args[2]&0777U&~b->creation_mask) : 0600U;
        file=b->family->mount.open(b->family->mount.context,m->path,
            flags&(O_ACCMODE|O_CREAT|O_EXCL|O_TRUNC|O_APPEND),mode);
        if (file>=0) {
            struct stat actual;
            if (fstat(file,&actual)<0) rc=-errno;
            else if (!S_ISREG(actual.st_mode)) rc=-EOPNOTSUPP;
            else {
                int status=fcntl(file,F_GETFL);
                if (status<0) rc=-errno;
                else if ((status&O_ACCMODE)!=access || (status&O_PATH)) rc=-EACCES;
                else if (fcntl(file,F_SETFD,FD_CLOEXEC)<0 ||
                         fcntl(file,F_SETFL,(status&~O_APPEND)|(flags&O_APPEND)|O_NONBLOCK)<0) rc=-errno;
                else if (!exists) rc=mount_stat(b,m->path,&st);
            }
            if (rc<0) { close(file); file=rc; }
        }
    }
    if (file<0) { release_status(state); return file; }
    m->attributes=st;
    state->guest_nonblock=flags&O_NONBLOCK;
    b->files[slot]=file;
    b->status[slot]=state;
    b->descriptor_flags[slot]=(flags&O_CLOEXEC)?FD_CLOEXEC:0;
    b->no_truncate[slot]=mount_right(b,LL_TRUNCATE)<0;
    if (!directory && !path_only && (r->operation==SUCRUNE_BROKER_OPEN_READ || (exec && r->args[3])))
        *send_fd=file;
    return slot;
}
static int mount_entries(struct broker *b,struct mount_file *m,int file,struct sucrune_response *out,size_t capacity) {
    if (m->path_only) return -EBADF;
    if (!S_ISDIR(m->attributes.st_mode)) return -ENOTDIR;
    if (!m->listed) {
        int rc=same_mounted_directory(b,file,m->path);
        if (!rc) rc=b->family->mount.list(b->family->mount.context,m->path,&m->names,&m->count);
        if (rc<0) return rc;
        m->listed=true;
    }
    size_t bytes=0;
    while (m->cursor < m->count+2) {
        const char *name=m->cursor==0?".":m->cursor==1?"..":m->names[m->cursor-2];
        if (!name || !*name || (m->cursor>=2 && (!strcmp(name,".")||!strcmp(name,".."))) ||
            strlen(name)>255 || strpbrk(name,"/\\")) return -EIO;
        size_t length=strlen(name);
        uint16_t record=(uint16_t)((19U+length+1U+7U)&~7U);
        if (record>capacity-bytes) {
            if (!bytes) return -EINVAL;
            break;
        }
        uint64_t ino=1; int64_t pos=(int64_t)(m->cursor+1);
        unsigned char *data=out->data+bytes;
        memset(data,0,record);
        memcpy(data,&ino,8); memcpy(data+8,&pos,8); memcpy(data+16,&record,2);
        data[18]=m->cursor<2?4:0; /* DT_DIR or DT_UNKNOWN (Linux callers stat as needed). */
        memcpy(data+19,name,length);
        bytes+=record; ++m->cursor;
    }
    out->size=(uint32_t)bytes;
    return (int)bytes;
}
static int mount_access(struct broker *b,const struct stat *st,int rights) {
    if ((rights&W_OK) && b->write_scope==SUCRUNE_WRITE_READ_ONLY) return -EACCES;
    if ((rights&R_OK) && !(st->st_mode&0444)) return -EACCES;
    if ((rights&W_OK) && !(st->st_mode&0222)) return -EACCES;
    if ((rights&X_OK) && !(st->st_mode&0111)) return -EACCES;
    return 0;
}
static bool mount_fd_operation(struct broker *b,const struct sucrune_request *r,struct sucrune_response *out) {
    struct mount_file *m=mounted_file(b,r->args[0]);
    bool empty=r->size && !r->data[0];
    if (!m && empty && r->args[0]==AT_FDCWD && b->mount_cwd) {
        if (r->operation==SUCRUNE_BROKER_UTIMENSAT || r->operation==SUCRUNE_BROKER_LINKAT ||
            r->operation==SUCRUNE_BROKER_READLINKAT) {out->result=-EOPNOTSUPP; return true;}
        if (r->operation==SUCRUNE_BROKER_FACCESSAT2 && (r->args[2]&AT_EMPTY_PATH)) {
            struct stat st;
            out->result=mount_stat(b,b->mount_cwd,&st);
            if (out->result==0) out->result=mount_access(b,&st,(int)r->args[1]);
            return true;
        }
    }
    if (!m) return false;
    struct file_status *s=b->status[r->args[0]];
    int fd=b->files[r->args[0]];
    switch(r->operation) {
    case 80: {
        struct stat st=m->attributes;
        if (!m->path_only && S_ISREG(st.st_mode)) {
            struct stat actual;
            if (fstat(fd,&actual)<0) { out->result=-errno; return true; }
            st.st_size=actual.st_size; st.st_blocks=actual.st_blocks; st.st_mtim=actual.st_mtim;
        }
        stat_reply(out,&st); out->result=0; return true;
    }
    case 61:
        if (r->args[1]<0 || r->args[1]>SUCRUNE_IO_LIMIT) { out->result=-EINVAL; return true; }
        pthread_mutex_lock(&s->lock);
        out->result=mount_entries(b,m,fd,out,(size_t)r->args[1]);
        pthread_mutex_unlock(&s->lock); return true;
    case 62:
        if (!S_ISDIR(m->attributes.st_mode)) return false;
        pthread_mutex_lock(&s->lock);
        if (m->path_only) out->result=-EBADF;
        else if (r->args[2]==SEEK_CUR && r->args[1]==0) out->result=(int64_t)m->cursor;
        else if (r->args[2]==SEEK_SET && r->args[1]>=0 && (uint64_t)r->args[1]<=m->count+2U) {
            m->cursor=(size_t)r->args[1]; out->result=r->args[1];
            if (!m->cursor) {
                for (size_t i=0;i<m->count;++i) free(m->names[i]);
                free(m->names); m->names=NULL; m->count=0; m->listed=false;
            }
        } else out->result=-EINVAL;
        pthread_mutex_unlock(&s->lock); return true;
    case 25:
        if (m->path_only && (r->args[1]==F_GETFL || r->args[1]==F_SETFL)) {
            out->result=r->args[1]==F_GETFL ? O_PATH : -EBADF; return true;
        }
        return false;
    case 52: out->result=-EOPNOTSUPP; return true; /* fchmod */
    case SUCRUNE_BROKER_LINKAT:
    case SUCRUNE_BROKER_UTIMENSAT:
        if (!empty) return false;
        out->result=-EOPNOTSUPP; return true;
    case SUCRUNE_BROKER_READLINKAT:
        if (!empty) return false;
        out->result=-ENOENT; return true;
    case SUCRUNE_BROKER_FACCESSAT2:
        if (!empty || !(r->args[2]&AT_EMPTY_PATH)) return false;
        out->result=mount_access(b,&m->attributes,(int)r->args[1]); return true;
    default: return false;
    }
}
static int mount_rename(struct broker *b,const struct sucrune_request *r) {
    const char *source,*dest; size_t end;
    int rc=request_path(r,0,&source,&end);
    if (!rc) rc=request_path(r,end,&dest,&end);
    if (rc || end!=r->size || r->args[2] || r->args[3]) return rc?-rc:-EINVAL;
    char old[SUCRUNE_PATH_LIMIT],leaf[256]; bool trailing;
    int fd=walk_parent(b,r->args[0],source,false,true,leaf,&trailing);
    if (fd>=0) {close(fd);return -EXDEV;}
    if (fd!=MOUNT_TARGET) return fd;
    if (!*b->mount_path || b->mount_dot) return -EBUSY;
    strcpy(old,b->mount_path);
    struct stat src;
    rc=mount_stat(b,old,&src);
    if (rc<0) return rc;
    if (trailing && !S_ISDIR(src.st_mode)) return -ENOTDIR;
    fd=walk_parent(b,r->args[1],dest,false,true,leaf,&trailing);
    if (fd>=0) {close(fd);return -EXDEV;}
    if (fd!=MOUNT_TARGET) return fd;
    if (!*b->mount_path || b->mount_dot) return -EBUSY;
    if (trailing && !S_ISDIR(src.st_mode)) return -ENOTDIR;
    if (b->write_scope==SUCRUNE_WRITE_READ_ONLY) return -EACCES;
    unsigned int rights=S_ISDIR(src.st_mode) ? LL_REMOVE_DIR|LL_MAKE_DIR : LL_REMOVE_FILE|LL_MAKE_REG;
    const char *oldleaf=strrchr(old,'/'), *newleaf=strrchr(b->mount_path,'/');
    if ((oldleaf==NULL)!=(newleaf==NULL) || (oldleaf && newleaf &&
        (oldleaf-old!=newleaf-b->mount_path || strncmp(old,b->mount_path,(size_t)(oldleaf-old)))))
        rights|=LL_REFER;
    rc=mount_right(b,rights);
    if (rc<0) return rc;
    return b->family->mount.rename(b->family->mount.context,old,b->mount_path,0);
}
static int mount_path_operation(struct broker *b,const struct sucrune_request *r,
                                struct sucrune_response *out,int *send_fd) {
    int rc;
    switch(r->operation) {
    case 56: case SUCRUNE_BROKER_OPEN_READ: case SUCRUNE_BROKER_OPEN_EXEC:
        return mount_open(b,r,send_fd);
    case 38: return mount_rename(b,r);
    case 34: {
        struct stat existing;
        rc=mount_stat(b,b->mount_path,&existing);
        if (!rc) return -EEXIST;
        if (rc!=-ENOENT || !*b->mount_path || b->mount_dot) return rc;
        if (b->write_scope==SUCRUNE_WRITE_READ_ONLY) return -EACCES;
        rc=mount_right(b,LL_MAKE_DIR);
        return rc<0 ? rc : b->family->mount.mkdir(b->family->mount.context,b->mount_path);
    }
    case 35:
        if (!*b->mount_path || b->mount_dot) return -EBUSY;
        if (b->write_scope==SUCRUNE_WRITE_READ_ONLY) return -EACCES;
        if (r->args[1]!=0 && r->args[1]!=AT_REMOVEDIR) return -EINVAL;
        if (b->mount_requires_dir && r->args[1]!=AT_REMOVEDIR) return -EISDIR;
        rc=mount_right(b,r->args[1]?LL_REMOVE_DIR:LL_REMOVE_FILE);
        return rc<0 ? rc : b->family->mount.remove(b->family->mount.context,b->mount_path,r->args[1]!=0);
    case 36: case 53: case SUCRUNE_BROKER_UTIMENSAT: return -EOPNOTSUPP;
    case SUCRUNE_BROKER_LINKAT: return -EXDEV;
    case 79: case 49: case SUCRUNE_BROKER_FACCESSAT: case SUCRUNE_BROKER_FACCESSAT2: case SUCRUNE_BROKER_READLINKAT: {
        struct stat st;
        rc=mount_stat(b,b->mount_path,&st);
        if (rc<0) return rc;
        if (b->mount_requires_dir && !S_ISDIR(st.st_mode)) return -ENOTDIR;
        if (r->operation==SUCRUNE_BROKER_READLINKAT) return -EINVAL;
        if (r->operation==79) {
            if (r->args[1] && r->args[1]!=AT_SYMLINK_NOFOLLOW) return -EINVAL;
            stat_reply(out,&st); return 0;
        }
        if (r->operation==49) {
            if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
            int pin=pin_directory(b,b->mount_path);
            if (pin<0) return pin;
            char *cwd=strdup(b->mount_path);
            if (!cwd) { close(pin); return -ENOMEM; }
            free(b->mount_cwd); b->mount_cwd=cwd;
            close(b->cwd); b->cwd=pin; return 0;
        }
        return mount_access(b,&st,(int)r->args[1]);
    }
    default: return -EOPNOTSUPP;
    }
}
