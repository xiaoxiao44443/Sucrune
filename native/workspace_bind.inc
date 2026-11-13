/* Constructor paths come from the manager. Pin every guest-relative component
 * without following symlinks, including the mountpoint supplied by its owner. */
static int canonical_relative(const char *path) {
    if (!path || !*path || strlen(path)>=SUCRUNE_PATH_LIMIT) return -EINVAL;
    for (const char *p=path;;) {
        const char *end=strchr(p,'/');
        size_t size=end ? (size_t)(end-p) : strlen(p);
        if (!size || size>NAME_MAX || (size==1 && *p=='.') ||
            (size==2 && !memcmp(p,"..",2)) || memchr(p,'\\',size)) return -EINVAL;
        if (!end) return 0;
        p=end+1;
    }
}
static int pin_components(int root,const char *relative,size_t length) {
    int parent=fcntl(root,F_DUPFD_CLOEXEC,3);
    if (parent<0) return -errno;
    for (size_t i=0;i<length;) {
        size_t j=i;
        while (j<length && relative[j]!='/') ++j;
        char part[NAME_MAX+1];
        memcpy(part,relative+i,j-i);part[j-i]='\0';
        int next=openat(parent,part,O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        int error=errno;
        close(parent);
        if (next<0) return -error;
        parent=next;
        i=j+1;
    }
    return parent;
}
static int attach_bind(struct broker *b,const char *owner,const char *subdir,const char *target) {
    if (owner[0]!='/' || target[0]!='/' || canonical_relative(subdir) ||
        canonical_relative(target+1) || (b->family->mount.stat && !strcmp(target,"/workspace"))) return -EINVAL;
    int source=open(owner,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (source<0) return -errno;
    char path[PATH_MAX],guest[PATH_MAX];
    int rc=descriptor_name(source,path);
    if (!rc) rc=descriptor_name(b->root,guest);
    if (!rc && (under_root(path,guest) || under_root(guest,path))) rc=-EINVAL;
    if (!rc) rc=sucrune_links_init(&b->bind_links,source,owner);
    if (!rc) {
        rc=pin_components(source,subdir,strlen(subdir));
        if (rc>=0) {b->family->bind_root=rc;rc=0;}
    }
    close(source);
    if (rc<0) return rc;
    b->family->bind_target=strdup(target);
    if (!b->family->bind_target) return -ENOMEM;
    const char *slash=strrchr(target,'/');
    b->family->bind_name=strrchr(b->family->bind_target,'/')+1;
    b->family->bind_in_workspace=b->family->mount.stat && !strncmp(target,"/workspace/",11);
    if (b->family->bind_in_workspace) {
        struct stat placeholder;
        rc=mount_stat(b,target+11,&placeholder);
        if (rc<0 || !S_ISDIR(placeholder.st_mode)) return rc<0 ? rc : -ENOTDIR;
        rc=fcntl(b->family->mount_anchor,F_DUPFD_CLOEXEC,3);
        if (rc<0) return -errno;
    } else {
        rc=pin_components(b->root,target+1,slash==target?0:(size_t)(slash-target-1));
        if (rc<0) return rc;
        struct stat placeholder;
        int error=fstatat(rc,slash+1,&placeholder,AT_SYMLINK_NOFOLLOW)<0 ? -errno :
            S_ISDIR(placeholder.st_mode) ? 0 : -ENOTDIR;
        if (error) {close(rc);return error;}
    }
    b->family->bind_parent=rc;
    b->domain.bind_root_plus_one=b->family->bind_root+1;
    b->domain.bind_parent_plus_one=b->family->bind_parent+1;
    return 0;
}
/* Distinct broker families may bind each other in reverse. Their namespace
 * operations and ledger updates must always acquire both locks in inode order. */
static int order_namespace_locks(struct broker *b) {
    b->first_lock=b->links.parent;
    b->second_lock=-1;
    if (!b->family->bind_target) return 0;
    struct stat local,owner;
    if (fstat(b->links.parent,&local)<0 || fstat(b->bind_links.parent,&owner)<0) return -errno;
    if (local.st_dev==owner.st_dev && local.st_ino==owner.st_ino) return 0;
    if (local.st_dev<owner.st_dev || (local.st_dev==owner.st_dev && local.st_ino<owner.st_ino))
        b->second_lock=b->bind_links.parent;
    else {b->first_lock=b->bind_links.parent;b->second_lock=b->links.parent;}
    return 0;
}
static int lock_namespace(struct broker *b,int mode) {
    if (flock(b->first_lock,mode)<0) return -errno;
    if (b->second_lock>=0 && flock(b->second_lock,mode)<0) {
        int rc=-errno;
        (void)flock(b->first_lock,LOCK_UN);
        return rc;
    }
    return 0;
}
static void unlock_namespace(struct broker *b) {
    if (b->second_lock>=0) (void)flock(b->second_lock,LOCK_UN);
    (void)flock(b->first_lock,LOCK_UN);
}
