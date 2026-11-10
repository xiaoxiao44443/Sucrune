#include "workspace_broker.h"
#include "guest_directory.h"
#include "trusted_exec_image.h"
#include "guest_landlock.h"
#include "workspace_links.h"
#include "workspace_locks.h"
#include "guest_abi.h"
#include "guest_proc.h"
#include "network_broker.h"
#include "pty_broker.h"
#include "broker_transport.h"
#include "dns_proxy.h"
#if defined(__ANDROID__)
#include <android/multinetwork.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/vfs.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FILE_SLOTS ((int)(SUCRUNE_BROKER_HANDLE_BASE + SUCRUNE_FILE_RESOURCES))
_Static_assert(FILE_SLOTS == SUCRUNE_BROKER_HANDLE_BASE + SUCRUNE_FILE_RESOURCES,
               "broker capacity must cover every guest file description");
struct broker_family {
    atomic_uint sessions;
    struct sucrune_guest_directory mount;
    int mount_anchor;
};
struct mount_file {
    char *path;
    struct stat attributes;
    char **names;
    size_t count, cursor;
    bool listed, path_only;
};
#define MOUNT_TARGET (-8193)
struct file_status {
    atomic_uint refs;
    pthread_mutex_t lock;
    int guest_nonblock;
    int proc_table;
    /* A read-only snapshot of a base file retains its project dentry identity.
     * The shared host inode must never be a mutation or per-project lock target. */
    ino_t base_ino;
    int base_anchor_plus_one;
    int private_pin_plus_one;
    /* A sealed executable supplies bytes and length. Execution eligibility
     * is decided from the pinned guest file's actual mode and ownership. */
    mode_t image_mode;
    uid_t image_uid;
    gid_t image_gid;
    struct mount_file *mounted;
};
struct broker {
    int socket, root, completion;
    mode_t creation_mask;
    unsigned int resource_limit;
    enum sucrune_workspace_profile profile;
    enum sucrune_write_scope write_scope;
    struct sucrune_workspace_links links;
    int files[FILE_SLOTS];
    int descriptor_flags[FILE_SLOTS];
    struct file_status *status[FILE_SLOTS];
    unsigned char exec_record_close[FILE_SLOTS];
    struct sucrune_record_locks record_locks;
    struct broker_family *family;
    struct sucrune_network_broker network;
    struct sucrune_pty_broker ptys;
    struct sucrune_dns_proxy *dns;
    unsigned char *bulk_bytes;
    size_t bulk_length, bulk_sent;
    struct {
        unsigned char *bytes;
        size_t length, received;
        int slot;
        off_t offset; /* -1 uses the shared open-description position. */
    } upload;
    uint64_t network_handle;
    int cwd;
    char *mount_cwd;
    char mount_path[SUCRUNE_PATH_LIMIT];
    bool mount_requires_dir, mount_dot;
    unsigned int walk_depth;
    struct ll_domain domain;
    struct ll_ruleset *rulesets[FILE_SLOTS];
    bool no_truncate[FILE_SLOTS];
    struct sucrune_exec_image *trusted_exec;
};
static void release_status(struct file_status *state) {
    if(state!=NULL && atomic_fetch_sub_explicit(&state->refs,1U,memory_order_acq_rel)==1U) {
        if (state->base_anchor_plus_one) close(state->base_anchor_plus_one - 1);
        if (state->private_pin_plus_one) close(state->private_pin_plus_one - 1);
        struct mount_file *m = state->mounted;
        if (m) {
            for (size_t i=0; i<m->count; ++i) free(m->names[i]);
            free(m->names); free(m->path); free(m);
        }
        (void)pthread_mutex_destroy(&state->lock);free(state);
    }
}
static void release_family(struct broker_family *family) {
    if(family!=NULL && atomic_fetch_sub_explicit(&family->sessions,1U,memory_order_acq_rel)==1U) {
        if (family->mount.destroy) family->mount.destroy(family->mount.context);
        if (family->mount_anchor>=0) close(family->mount_anchor);
        free(family);
    }
}
static void discard_upload(struct broker *b) {
    free(b->upload.bytes);
    memset(&b->upload,0,sizeof(b->upload));
}
static int close_file(struct broker *b,int slot) {
    if (b->rulesets[slot]) {
        ll_put(b->rulesets[slot]);
        b->rulesets[slot] = NULL;
        b->descriptor_flags[slot] = 0;
        return 0;
    }
    b->no_truncate[slot] = false;
    if(b->upload.slot==slot) discard_upload(b);
    int fd=b->files[slot];b->files[slot]=-1;b->descriptor_flags[slot]=0;b->exec_record_close[slot]=0;
    release_status(b->status[slot]);b->status[slot]=NULL;
    return close(fd)==0 ? 0 : -errno;
}
static int select_outbound_network(void *context,int fd) {
    struct broker *b=context;
    if (b->network_handle==0U) return 0;
#if defined(__ANDROID__)
    return android_setsocknetwork(b->network_handle,fd)==0 ? 0 : -errno;
#else
    (void)fd;return -ENOTSUP;
#endif
}
static int add_dns_client(void *context,int type,int fd,uint64_t token) {
    struct broker *b=context;
    return sucrune_dns_proxy_allow_client(b->dns,type==SOCK_STREAM ? SUCRUNE_DNS_TCP : SUCRUNE_DNS_UDP,fd,token);
}
static void remove_dns_client(void *context,uint64_t token) {
    struct broker *b=context;(void)sucrune_dns_proxy_remove_client(b->dns,token);
}
static void stop_dns(struct broker *b) {
    if (b->dns==NULL) return;
    sucrune_dns_proxy_request_stop(b->dns);
    /* The detached manager broker still owns the completion writer and proxy.
     * Never release either on a timeout: a stuck system IPC is not cleanup.
     * This loop is only reached after control EOF, never during file dispatch. */
    for (;;) {
        int result=sucrune_dns_proxy_join(b->dns,1000,NULL);
        if (result==0 && sucrune_dns_proxy_destroy(b->dns)==0) break;
        if (result!=-ETIMEDOUT) {
            /* An unexpected join error must not crash the shared manager or
             * signal a false successful barrier. Retain ownership and retry. */
            struct timespec backoff={1,0};(void)nanosleep(&backoff,NULL);
        }
    }
    b->dns=NULL;
}

static unsigned int file_and_pty_count(const struct broker *b) {
    unsigned int count = 0U;
    for (int i = 3; i < FILE_SLOTS; i++) if (b->files[i] >= 0 || b->rulesets[i]) count++;
    for (size_t i = 0; i < SUCRUNE_PTY_ENDPOINTS; ++i) if (b->ptys.slots[i] != NULL) count++;
    return count;
}

static int free_slot(const struct broker *b) {
    if (file_and_pty_count(b) + b->network.count >= b->resource_limit) return -EMFILE;
    for (int i = 3; i < FILE_SLOTS; i++)
        if (b->files[i] < 0 && !b->rulesets[i]) return i;
    return -EMFILE;
}
static int request_path(const struct sucrune_request *r, size_t offset, const char **path, size_t *next) {
    if (offset >= r->size) return EINVAL;
    const unsigned char *nul = memchr(r->data + offset, 0, r->size - offset);
    if (nul == NULL || (size_t)(nul - (r->data + offset)) >= SUCRUNE_PATH_LIMIT) return ENAMETOOLONG;
    *path = (const char *)r->data + offset;
    *next = (size_t)(nul - r->data) + 1U;
    return 0;
}

static int host_file(struct broker *b, int64_t guest) {
    if (guest < 3 || guest >= FILE_SLOTS || b->files[guest] < 0) { errno = EBADF; return -1; }
    return b->files[guest];
}

static int shared_mapping_file(struct broker *b, const struct sucrune_request *r) {
    if (r->size != 0 || r->reserved || (r->args[1] != 0 && r->args[1] != 1) ||
        r->args[2] || r->args[3]) return -EINVAL;
    int fd = host_file(b, r->args[0]);
    if (fd < 0) return -errno;
    struct stat st;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fstat(fd, &st) < 0) return -errno;
    if (!S_ISREG(st.st_mode)) return -ENODEV;
    int mode = flags & O_ACCMODE;
    if ((flags & O_PATH) || (mode != O_RDONLY && mode != O_RDWR) ||
        (r->args[1] && mode != O_RDWR)) return -EACCES;
    return fd;
}

static void stat_reply(struct sucrune_response *out, const struct stat *st) {
    struct sucrune_arm64_stat value = {
        .device = (uint64_t)st->st_dev, .inode = (uint64_t)st->st_ino,
        .mode = (uint32_t)st->st_mode, .nlink = (uint32_t)st->st_nlink,
        .uid = (uint32_t)st->st_uid, .gid = (uint32_t)st->st_gid,
        .rdevice = (uint64_t)st->st_rdev, .size = (int64_t)st->st_size,
        .block_size = (int32_t)st->st_blksize, .blocks = (int64_t)st->st_blocks,
        .atime_sec = st->st_atim.tv_sec, .atime_nsec = (uint64_t)st->st_atim.tv_nsec,
        .mtime_sec = st->st_mtim.tv_sec, .mtime_nsec = (uint64_t)st->st_mtim.tv_nsec,
        .ctime_sec = st->st_ctim.tv_sec, .ctime_nsec = (uint64_t)st->st_ctim.tv_nsec,
    };
    memcpy(out->data, &value, sizeof(value)); out->size = sizeof(value);
}

/* Walk one Linux component at a time. Only single names are handed to
 * openat, always with O_NOFOLLOW. Absolute link targets restart at the project
 * root, and relative targets restart in the link's containing directory. */
static int directory_base(struct broker *b, int64_t dir, const char *path) {
    int fd = path[0] == '/' ? b->root : dir == AT_FDCWD ? b->cwd : host_file(b, dir);
    if (fd < 0) return -errno;
    /* The root and cwd are already pinned directory descriptors. A caller's
     * directory argument can reference any file in its guest descriptor table. */
    if (path[0] != '/' && dir != AT_FDCWD) {
        struct stat st;
        if (fstat(fd, &st) < 0) return -errno;
        if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
    }
    int result = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    return result < 0 ? -errno : result;
}
static int same_inode(int left, int right) {
    struct stat a, b;
    if (fstat(left, &a) < 0 || fstat(right, &b) < 0) return -errno;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
static struct mount_file *mounted_file(struct broker *b,int64_t fd) {
    return fd>=3 && fd<FILE_SLOTS && b->files[fd]>=0 && b->status[fd] ? b->status[fd]->mounted : NULL;
}
static int walk_mount(struct broker *,const char *,const char *,bool,bool,char *,bool *);
static int same_mounted_directory(struct broker *,int,const char *);
static int walk_parent(struct broker *b, int64_t dir, const char *path, bool follow,
                       bool mutation, char *leaf, bool *trailing) {
    if (!*path) return -ENOENT;
    if (b->family->mount.stat && path[0]!='/') {
        struct mount_file *file=mounted_file(b,dir);
        if (file && !S_ISDIR(file->attributes.st_mode)) return -ENOTDIR;
        const char *start=dir==AT_FDCWD ? b->mount_cwd : file ? file->path : NULL;
        if (start) {
            int pin=dir==AT_FDCWD ? b->cwd : b->files[dir];
            int valid=same_mounted_directory(b,pin,start);
            return valid<0 ? valid : walk_mount(b,start,path,follow,mutation,leaf,trailing);
        }
    }
    char pending[SUCRUNE_PATH_LIMIT], link[SUCRUNE_PATH_LIMIT];
    size_t length = strlen(path);
    if (length >= sizeof(pending)) return -ENAMETOOLONG;
    memcpy(pending, path, length + 1);
    int parent = directory_base(b, dir, path);
    if (parent < 0) return parent;
    unsigned int hops = 0;
    int error = 0;
    char *cursor = pending;
    for (;;) {
        while (*cursor == '/') cursor++;
        char *end = cursor;
        while (*end && *end != '/') end++;
        size_t count = (size_t)(end - cursor);
        if (count > 255U) { error = ENAMETOOLONG; break; }
        if (memchr(cursor, '\\', count)) { error = EINVAL; break; }
        memcpy(leaf, cursor, count); leaf[count] = '\0';
        if (!count) strcpy(leaf, ".");
        char *rest = end;
        while (*rest == '/') rest++;
        bool last = !*rest;
        *trailing = last && end != rest;
        if (b->family->mount.stat && !strcmp(leaf,"workspace")) {
            int root=same_inode(parent,b->root);
            if (root!=0) {
                close(parent);
                return root<0 ? root : walk_mount(b,"",end,follow,mutation,leaf,trailing);
            }
        }
        if (strcmp(leaf, "..") == 0) {
            int at_root = same_inode(parent, b->root);
            if (at_root != 0) { error = at_root < 0 ? -at_root : EPERM; break; }
            int higher = openat(parent, "..", O_DIRECTORY | O_PATH | O_NOFOLLOW | O_CLOEXEC);
            if (higher < 0) { error = errno; break; }
            (void)close(parent); parent = higher;
            strcpy(leaf, ".");
        }
        if (last && !follow && (mutation || !*trailing)) return parent;
        if (last) {
            /* The caller operates on this single name with O_NOFOLLOW or
             * AT_SYMLINK_NOFOLLOW. Only links need pinning and guest resolution. */
            struct stat leaf_stat;
            if (fstatat(parent, leaf, &leaf_stat, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno == ENOENT) return parent;
                error = errno; break;
            }
            if (!S_ISLNK(leaf_stat.st_mode)) {
                if (*trailing && !S_ISDIR(leaf_stat.st_mode)) { error = ENOTDIR; break; }
                return parent;
            }
        }
        if (!last) {
            /* Pin an ordinary directory in one lookup. Symlinks (including
             * managed link markers) still go through guest resolution below. */
            int directory = openat(parent, leaf, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (directory >= 0) {
                close(parent); parent = directory; cursor = rest;
                continue;
            }
            if (errno != ENOTDIR && errno != ELOOP) { error = errno; break; }
        }
        int pinned = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (pinned < 0) {
            if (last && errno == ENOENT) return parent;
            error = errno; break;
        }
        /* Internal hard-link markers represent ordinary files even for lstat,
         * and must never be expanded as guest text. */
        pinned = sucrune_links_target(&b->links, pinned);
        if (pinned < 0) { error = -pinned; break; }
        struct stat st;
        if (fstat(pinned, &st) < 0) { error = errno; close(pinned); break; }
        if (S_ISLNK(st.st_mode)) {
            ssize_t n = readlinkat(pinned, "", link, sizeof(link));
            if (n < 0) error = errno;
            (void)close(pinned);
            if (error) break;
            if (++hops > 40U) { error = ELOOP; break; }
            size_t tail = strlen(end);
            if ((size_t)n + tail >= sizeof(pending)) { error = ENAMETOOLONG; break; }
            memmove(pending + n, end, tail + 1U);
            memcpy(pending, link, (size_t)n);
            if (pending[0] == '/') {
                int root = directory_base(b, AT_FDCWD, "/");
                if (root < 0) { error = -root; break; }
                (void)close(parent); parent = root;
            }
            cursor = pending;
            continue;
        }
        if ((!last || *trailing) && !S_ISDIR(st.st_mode)) {
            close(pinned); error = ENOTDIR; break;
        }
        if (last) { close(pinned); return parent; }
        close(parent); parent = pinned; cursor = rest;
    }
    close(parent);
    return -error;
}
static int query_target(struct broker *b, int64_t directory, const char *path, bool empty_allowed, bool follow,
                        bool require_link) {
    if (!*path) {
        if (!empty_allowed) return -ENOENT;
        int fd = directory == AT_FDCWD ? b->cwd : host_file(b, directory);
        if (fd < 0) return -errno;
        int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        return copy < 0 ? -errno : copy;
    }
    char leaf[256];
    bool trailing;
    int parent = walk_parent(b, directory, path, follow, false, leaf, &trailing);
    if (parent < 0) return parent;
    if (require_link && !trailing) {
        struct stat st;
        if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            int error = errno; (void)close(parent); return -error;
        }
        if (!S_ISLNK(st.st_mode)) { (void)close(parent); return -EINVAL; }
    }
    int target = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC | (trailing ? O_DIRECTORY : 0));
    int error = errno;
    (void)close(parent);
    return target < 0 ? -error : sucrune_links_target(&b->links, target);
}

/* Expand only manager-controlled proc magic links for getcwd. Return the
 * pathname relative to the pinned project root after rename in any broker. */
static int descriptor_name(int fd, char *name) {
    char proc[48];
    (void)snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, name, PATH_MAX);
    if (n < 0) return -errno;
    if (n >= PATH_MAX) return -ENAMETOOLONG;
    name[n] = '\0';
    return 0;
}

/* Authorize the physical object after guest link resolution. For namespace
 * changes the caller passes the pinned parent; for data/metadata it passes
 * the pinned target. Managed hard links reside in a separate backing store. */
enum write_area { AREA_PROTECTED, AREA_WORKSPACE, AREA_TMP };
static int write_area(struct broker *b, int fd) {
    char root[PATH_MAX], target[PATH_MAX];
    int rc = descriptor_name(b->root, root);
    if (rc == 0) rc = descriptor_name(fd, target);
    if (rc < 0) return rc;
    size_t n = strlen(root);
    if (strncmp(target, root, n) != 0) return AREA_PROTECTED;
    const char *relative = target + n;
    size_t length = strlen(relative);
    const char deleted[] = " (deleted)";
    if (length >= sizeof(deleted)-1 && !strcmp(relative + length - (sizeof(deleted)-1), deleted)) {
        // proc appends this suffix to an unlinked dentry, even if another alias remains.
        struct stat pinned, visible;
        if (fstat(fd,&pinned) || lstat(target,&visible) || pinned.st_dev!=visible.st_dev ||
            pinned.st_ino!=visible.st_ino) return AREA_PROTECTED;
    }
    if (strcmp(relative, "/workspace") == 0 || strncmp(relative, "/workspace/", 11) == 0) return AREA_WORKSPACE;
    if (strcmp(relative, "/tmp") == 0 || strncmp(relative, "/tmp/", 5) == 0) return AREA_TMP;
    return AREA_PROTECTED;
}
static int write_access(struct broker *b, int fd) {
    if (b->write_scope == SUCRUNE_WRITE_UNRESTRICTED) return 0;
    if (b->write_scope == SUCRUNE_WRITE_READ_ONLY) return -EACCES;
    struct stat st;
    if (fstat(fd, &st) < 0) return -errno;
    if (!st.st_nlink) return -EACCES;
    int area=write_area(b,fd);
    if (area<0) return area;
    if (area!=AREA_PROTECTED && (S_ISDIR(st.st_mode) || st.st_nlink==1)) return 0;
    if (!S_ISREG(st.st_mode) || area==AREA_WORKSPACE) return -EACCES;
    // A writable alias cannot grant access to other names outside the private temp tree.
    return sucrune_links_tmp_write(&b->links,b->root,&st,area==AREA_TMP);
}
static int current_directory(struct broker *b, struct sucrune_response *out) {
    if (b->mount_cwd) {
        int valid=same_mounted_directory(b,b->cwd,b->mount_cwd);
        if (valid<0) return valid;
        struct stat state;
        int rc=b->family->mount.stat(b->family->mount.context,b->mount_cwd,&state);
        if (rc<0 || !S_ISDIR(state.st_mode)) return rc<0 ? rc : -ENOENT;
        int size=snprintf((char *)out->data,sizeof(out->data),"/workspace%s%s",*b->mount_cwd?"/":"",b->mount_cwd);
        if (size<0 || (size_t)size>=SUCRUNE_PATH_LIMIT) return -ENAMETOOLONG;
        out->size=(uint32_t)size+1;return (int)out->size;
    }
    char root[PATH_MAX], cwd[PATH_MAX];
    struct stat st;
    if (fstat(b->cwd, &st) < 0) return -errno;
    if (st.st_nlink == 0) return -ENOENT;
    int rc = descriptor_name(b->root, root);
    if (rc == 0) rc = descriptor_name(b->cwd, cwd);
    if (rc < 0) return rc;
    size_t n = strlen(root);
    if (strncmp(root, cwd, n) || (cwd[n] && cwd[n] != '/')) return -EPERM;
    const char *relative = cwd[n] ? cwd + n : "/";
    size_t bytes = strlen(relative) + 1U;
    if (bytes > SUCRUNE_PATH_LIMIT) return -ENAMETOOLONG;
    memcpy(out->data, relative, bytes);
    out->size = (uint32_t)bytes;
    return (int)bytes;
}
static int64_t query_operation(struct broker *b, const struct sucrune_request *r, struct sucrune_response *out) {
    const char *path; size_t end;
    int error = request_path(r, 0U, &path, &end);
    if (error != 0) return -error;
    if (end != r->size || r->args[3] != 0) return -EINVAL;
    bool link = r->operation == SUCRUNE_BROKER_READLINKAT;
    if (link) {
        if (r->args[1] <= 0 || r->args[1] > SUCRUNE_IO_LIMIT || r->args[2] != 0) return -EINVAL;
    } else {
        const int allowed = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
        if (r->args[1] < 0 || (r->args[1] & ~(int64_t)(R_OK | W_OK | X_OK)) != 0 ||
            r->args[2] < 0 || (r->args[2] & ~(int64_t)allowed) != 0 ||
            (r->operation == SUCRUNE_BROKER_FACCESSAT && r->args[2] != 0)) return -EINVAL;
        /* Resolution uses effective credentials while access traditionally
         * uses real credentials. Android apps cannot change either identity;
         * reject a set-id host instead of bypassing its real-ID parent checks. */
        if (getuid() != geteuid() || getgid() != getegid()) return -ENOTSUP;
    }
    int target = query_target(b, r->args[0], path, link || (r->args[2] & AT_EMPTY_PATH) != 0,
                              !link && !(r->args[2] & AT_SYMLINK_NOFOLLOW), link);
    if (target < 0) return target;
    int64_t result;
    if (link) {
        struct stat st;
        if (fstat(target, &st) != 0) result = -errno;
        else if (!S_ISLNK(st.st_mode)) result = path[0] == '\0' ? -ENOENT : -EINVAL;
        else {
            ssize_t bytes = readlinkat(target, "", (char *)out->data, (size_t)r->args[1]);
            result = bytes < 0 ? -errno : (int64_t)bytes;
            if (bytes >= 0) out->size = (uint32_t)bytes;
        }
    } else if ((r->args[1] & W_OK) && (result = write_access(b, target)) < 0) {
        /* Report the same access the broker grants when opening for writing. */
    } else {
        struct stat st;
        if (fstat(target, &st) != 0) result = -errno;
        else if (S_ISLNK(st.st_mode)) result = (r->args[2] & AT_SYMLINK_NOFOLLOW) != 0 ? 0 : -ELOOP;
        else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) result = -EACCES;
        else {
            /* Old Android app seccomp can reject unknown faccessat2 entirely.
             * The fixed /proc path resolves only this already-pinned object;
             * the old kernel access syscall retains DAC/ACL/mount checks. */
            char pinned[64];
            int count = snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", target);
            if (count < 0 || (size_t)count >= sizeof(pinned)) result = -EIO;
            else result = faccessat(AT_FDCWD, pinned, (int)r->args[1], 0) == 0 ? 0 : -errno;
        }
    }
    (void)close(target); return result;
}

/* fchmod(O_PATH) returns EBADF. The kernel proc magic link binds the update
 * to this already pinned inode, including mode-000 objects owned by the app. */
static int chmod_pinned(int fd, mode_t mode) {
    char pinned[64];
    int n = snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", fd);
    if (n < 0 || (size_t)n >= sizeof(pinned)) return -EIO;
    return chmod(pinned, mode) == 0 ? 0 : -errno;
}

/* A read FD can outlive rename, unlink, or replacement. Resolve its pinned
 * marker under the exclusive workspace lock and compare identity before
 * detaching. Never apply FD metadata to a newer file at the same name. */
static int private_fd_target(struct broker *b, int64_t slot) {
    struct file_status *state = b->status[slot];
    if (state->private_pin_plus_one) {
        int cached = state->private_pin_plus_one - 1;
        int allowed = write_access(b, cached);
        if (allowed < 0) return allowed;
        int fd = fcntl(cached, F_DUPFD_CLOEXEC, 3);
        return fd < 0 ? -errno : fd;
    }
    int anchor = state->base_anchor_plus_one - 1;
    char root[PATH_MAX], name[PATH_MAX], leaf[256];
    int rc = descriptor_name(b->root, root);
    if (!rc) rc = descriptor_name(anchor, name);
    if (rc < 0) return rc;
    size_t n = strlen(root);
    if (strncmp(root, name, n) || name[n] != '/') return -ESTALE;
    bool trailing;
    int parent = walk_parent(b, AT_FDCWD, name + n, false, false, leaf, &trailing);
    if (parent < 0) return parent;
    struct stat a, p;
    if (fstat(anchor, &a)) rc = -errno;
    else if (fstatat(parent, leaf, &p, AT_SYMLINK_NOFOLLOW) || a.st_dev != p.st_dev || a.st_ino != p.st_ino) rc = -ESTALE;
    else rc = write_access(b, parent);
    if (!rc) {
        rc = sucrune_base_promote(&b->links, parent, leaf);
        if (!rc) rc = -ESTALE;
    }
    if (rc > 0) {
        int pin = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (pin < 0) rc = -errno;
        else {
            state->private_pin_plus_one = pin + 1;
            rc = fcntl(pin, F_DUPFD_CLOEXEC, 3);
            if (rc < 0) rc = -errno;
        }
    }
    close(parent);
    return rc;
}

static int mutable_target(struct broker *b, int64_t directory, const char *path, bool empty, bool follow) {
    if (!*path) {
        if (empty && directory != AT_FDCWD && host_file(b, directory) >= 0 && b->status[directory]->base_ino)
            return private_fd_target(b, directory);
        return query_target(b, directory, path, empty, follow, false);
    }
    char leaf[256];
    bool trailing;
    int parent = walk_parent(b, directory, path, follow, false, leaf, &trailing);
    if (parent < 0) return parent;
    int flags = O_PATH | O_CLOEXEC | O_NOFOLLOW | (trailing ? O_DIRECTORY : 0);
    int target = openat(parent, leaf, flags);
    ino_t base_ino = 0;
    target = target < 0 ? -errno : sucrune_links_target_info(&b->links, target, &base_ino);
    if (target >= 0 && base_ino) {
        close(target);
        target = write_access(b, parent);
        if (!target) target = sucrune_base_promote(&b->links, parent, leaf);
        if (target >= 0) {
            target = openat(parent, leaf, flags);
            if (target < 0) target = -errno;
        }
    }
    close(parent);
    return target;
}

static int chmod_project_path(struct broker *b, const struct sucrune_request *r) {
    const char *path;
    size_t end;
    int error = request_path(r, 0, &path, &end);
    if (error != 0) return -error;
    if (end != r->size || r->reserved != 0 || (r->args[1] & ~INT64_C(0777)) != 0 ||
        r->args[2] != 0 || r->args[3] != 0) return -EINVAL;
    int fd = mutable_target(b, r->args[0], path, false, true);
    if (fd < 0) return fd;
    struct stat st;
    if (fstat(fd, &st) != 0) error = errno;
    else if (S_ISLNK(st.st_mode)) error = ELOOP;
    else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) error = EACCES;
    else if ((error = -write_access(b, fd)) == 0) error = -chmod_pinned(fd, (mode_t)r->args[1]);
    (void)close(fd);
    return -error;
}

static int utimens_project(struct broker *b, const struct sucrune_request *r) {
    const char *path;
    size_t end;
    int error = request_path(r, 0, &path, &end);
    if (error != 0) return -error;
    struct timespec times[2];
    _Static_assert(sizeof(times) == 32U, "AArch64 timespec wire size");
    if (r->reserved != 0U || r->args[3] != 0 || (r->args[2] != 0 && r->args[2] != 1) ||
        r->size - end != (r->args[2] ? sizeof(times) : 0U)) return -EINVAL;
    if (r->args[2]) {
        memcpy(times, r->data + end, sizeof(times));
        if (times[0].tv_nsec == UTIME_OMIT && times[1].tv_nsec == UTIME_OMIT) return 0;
    }
    if ((r->args[1] & ~(int64_t)(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) != 0) return -EINVAL;
    if (r->args[2]) {
        for (size_t i = 0; i < 2; ++i) {
            long ns = times[i].tv_nsec;
            if ((ns < 0 || ns >= 1000000000L) && ns != UTIME_NOW && ns != UTIME_OMIT) return -EINVAL;
        }
    }
    int target = mutable_target(b, r->args[0], path, (r->args[1] & AT_EMPTY_PATH) != 0,
                                !(r->args[1] & AT_SYMLINK_NOFOLLOW));
    if (target < 0) return target;
    struct stat st;
    if ((error = -write_access(b, target)) != 0) { close(target); return -error; }
    if (fstat(target, &st) != 0) error = errno;
    else if (S_ISLNK(st.st_mode)) {
        if ((r->args[1] & AT_SYMLINK_NOFOLLOW) == 0) error = ELOOP;
        /* Older kernels lack empty-path utimensat. A pinned symlink must never
         * be reopened through its guest name or followed to an external inode. */
        else if (utimensat(target, "", r->args[2] ? times : NULL, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0)
            error = errno == EINVAL ? ENOTSUP : errno;
    } else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) error = EACCES;
    else {
        char pinned[64];
        int count = snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", target);
        if (count < 0 || (size_t)count >= sizeof(pinned)) error = EIO;
        else if (utimensat(AT_FDCWD, pinned, r->args[2] ? times : NULL, 0) != 0) error = errno;
    }
    (void)close(target);
    return -error;
}

static int protected_directory(struct broker *b, int parent, const char *leaf) {
    int target = openat(parent, leaf, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (target < 0) return -errno;
    int at_root = same_inode(target, b->root);
    int result = at_root ? (at_root < 0 ? at_root : -EPERM) : 0;
    int current = directory_base(b, AT_FDCWD, ".");
    while (result == 0 && current >= 0) {
        int match = same_inode(current, target);
        if (match) { result = match < 0 ? match : -EBUSY; break; }
        match = same_inode(current, b->root);
        if (match) { if (match < 0) result = match; break; }
        int higher = openat(current, "..", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int previous_root = higher < 0 ? -errno : same_inode(higher, current);
        close(current); current = higher;
        if (previous_root) { result = previous_root < 0 ? previous_root : -EPERM; break; }
    }
    if (current >= 0) close(current);
    else if (result == 0) result = current;
    close(target);
    return result;
}
static int name_destination(struct broker *b, int64_t dir, const char *path, char *leaf) {
    bool trailing;
    int parent = walk_parent(b, dir, path, false, true, leaf, &trailing);
    if (parent < 0) return parent;
    if (trailing || !strcmp(leaf, ".")) {
        struct stat st;
        int result = fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) < 0 ? -errno : -EEXIST;
        close(parent);
        return result;
    }
    return parent;
}
static int64_t symlink_project(struct broker *b, const struct sucrune_request *r) {
    const char *target, *name;
    size_t end;
    int error = request_path(r, 0, &target, &end);
    if (!error) error = request_path(r, end, &name, &end);
    if (error) return -error;
    if (end != r->size || r->reserved || r->args[1] || r->args[2] || r->args[3]) return -EINVAL;
    if (!*target) return -ENOENT;
    if (!strncmp(target, SUCRUNE_INODE_MARKER_PREFIX, sizeof(SUCRUNE_INODE_MARKER_PREFIX)-1U)) return -EPERM;
    if (!strncmp(target, SUCRUNE_BASE_MARKER_PREFIX, sizeof(SUCRUNE_BASE_MARKER_PREFIX)-1U)) return -EPERM;
    char leaf[256];
    int parent = name_destination(b, r->args[0], name, leaf);
    if (parent < 0) return parent;
    int rc = write_access(b, parent);
    if (!rc) rc = ll_check(&b->domain, b->root, parent, LL_NO_TARGET, LL_MAKE_SYM);
    if (!rc && symlinkat(target, parent, leaf) != 0) rc = -errno;
    close(parent);
    return rc;
}
static int64_t link_project_file(struct broker *b, const struct sucrune_request *r) {
    if (b->write_scope == SUCRUNE_WRITE_READ_ONLY) return -EACCES;
    bool scoped = b->write_scope == SUCRUNE_WRITE_PROJECT;
    const int allowed = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;
    if (r->reserved || r->args[3] || (r->args[2] & ~(int64_t)allowed)) return -EINVAL;
    const char *source, *dest;
    size_t end;
    int error = request_path(r, 0, &source, &end);
    if (!error) error = request_path(r, end, &dest, &end);
    if (error) return -error;
    if (end != r->size) return -EINVAL;
    if (scoped && !*source) return -EACCES;
    bool follow = (r->args[2] & AT_SYMLINK_FOLLOW) != 0, trailing;
    int file = query_target(b, r->args[0], source, (r->args[2] & AT_EMPTY_PATH) != 0, follow, false);
    if (file < 0) return file;
    struct stat st;
    int rc = 0;
    if (fstat(file, &st) < 0) rc = -errno;
    else if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) rc = -EPERM;
    char leaf[256], oldleaf[256];
    int destfd = rc < 0 ? rc : name_destination(b, r->args[1], dest, leaf);
    if (destfd < 0) rc = destfd;
    else if (scoped && (!S_ISREG(st.st_mode) || write_area(b,destfd)!=AREA_TMP)) rc = -EACCES;
    else if ((rc = ll_check(&b->domain, b->root, destfd, LL_NO_TARGET, ll_make_right(st.st_mode))) != 0) {
        /* No destination was created. */
    } else if (!*source) {
        /* An empty path drops the original dentry, needed for the REFER check. */
        if (b->domain.count || (r->args[0] != AT_FDCWD && b->status[r->args[0]]->base_ino)) rc = -EOPNOTSUPP;
        else rc = linkat(file, "", destfd, leaf, AT_EMPTY_PATH) == 0 ? 0 : -errno;
    }
    else {
        int old = walk_parent(b, r->args[0], source, follow, false, oldleaf, &trailing);
        if (old < 0) rc = old;
        else {
            if (scoped) rc = write_area(b,old)==AREA_TMP ? write_access(b,file) : -EACCES;
            if (!rc) rc = ll_reparent(&b->domain, b->root, old, file, destfd, st.st_mode);
            if (!rc && S_ISLNK(st.st_mode))
                rc = linkat(old, oldleaf, destfd, leaf, 0) == 0 ? 0 : -errno;
            else if (!rc) {
                rc = sucrune_base_promote(&b->links, old, oldleaf);
                if (rc > 0) {
                    close(file);
                    file = openat(old, oldleaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                    rc = file < 0 ? -errno : 0;
                }
                if (!rc) rc = sucrune_links_publish(&b->links, old, oldleaf, file, destfd, leaf);
            }
            close(old);
        }
    }
    if (destfd >= 0) close(destfd);
    close(file);
    return rc;
}
/* After guest symlink resolution, authorize the opened inode and its guest
 * hierarchy. Reopen the pinned file, so O_TRUNC cannot affect another inode.
 * For creation, O_EXCL prevents a competing creator from replacing the target
 * between the parent check and creation. */
static int landlock_open(struct broker *b, int parent, const char *leaf, int flags,
                         mode_t mode, bool exec, bool scoped, bool *no_truncate, ino_t *base_ino) {
    int pin = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (pin < 0) {
        if (errno != ENOENT || !(flags & O_CREAT)) return -errno;
        unsigned int required = LL_MAKE_REG;
        int access = flags & O_ACCMODE;
        if (access != O_WRONLY) required |= LL_READ_FILE;
        if (access != O_RDONLY) required |= LL_WRITE_FILE;
        if (flags & O_TRUNC) required |= LL_TRUNCATE;
        unsigned int allowed;
        int error = ll_allowed(&b->domain, b->root, parent, LL_NO_TARGET, &allowed);
        if (error) return error;
        if (required & ~allowed) return -EACCES;
        *no_truncate = !(allowed & LL_TRUNCATE);
        return sucrune_links_open(&b->links, parent, leaf, flags | O_EXCL, mode, base_ino);
    }
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) { close(pin); return -EEXIST; }
    pin = sucrune_links_target_info(&b->links, pin, base_ino);
    if (pin < 0) return pin;
    struct stat st;
    int result;
    if (fstat(pin, &st) < 0) result = -errno;
    else if (S_ISLNK(st.st_mode)) result = -ELOOP;
    else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) result = -EACCES;
    else {
        unsigned int required = exec ? LL_EXECUTE : 0U;
        int access = flags & O_ACCMODE;
        if (access != O_WRONLY) required |= S_ISDIR(st.st_mode) ? LL_READ_DIR : LL_READ_FILE;
        if (access != O_RDONLY) required |= LL_WRITE_FILE;
        if (flags & O_TRUNC) required |= LL_TRUNCATE;
        unsigned int allowed;
        /* File-specific rules follow the project's dentry, even when another
         * name maps the same immutable contents. */
        int anchor = -1;
        if (*base_ino) anchor = openat(parent, leaf, O_PATH | O_CLOEXEC | O_NOFOLLOW);
        if (*base_ino && anchor < 0) result = -errno;
        else result = ll_allowed(&b->domain, b->root, parent, anchor < 0 ? pin : anchor, &allowed);
        if (anchor >= 0) close(anchor);
        if (!result && (required & ~allowed)) result = -EACCES;
        if (!result && scoped) result = write_access(b, *base_ino ? parent : pin);
        if (!result && *base_ino && (access != O_RDONLY || (flags & O_TRUNC))) {
            result = sucrune_base_promote(&b->links, parent, leaf);
            if (result >= 0) {
                close(pin);
                pin = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                if (pin < 0) return -errno;
                *base_ino = 0;
                result = 0;
            }
        }
        if (!result) {
            *no_truncate = !(allowed & LL_TRUNCATE);
            char proc[48];
            (void)snprintf(proc, sizeof(proc), "/proc/self/fd/%d", pin);
            result = open(proc, (flags & ~(O_CREAT | O_EXCL | O_NOFOLLOW)) | (*base_ino ? O_NOATIME : 0));
            if (result < 0) result = -errno;
        }
    }
    close(pin);
    return result;
}
static int rename_rights(struct broker *b, int parent, const char *leaf, int dest,
                         const struct stat *replaced) {
    if (!b->domain.count) return 0;
    int src = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (src < 0) return -errno;
    src = sucrune_links_target(&b->links, src);
    if (src < 0) return src;
    struct stat st;
    int rc = fstat(src, &st) < 0 ? -errno : 0;
    if (!rc) rc = ll_check(&b->domain, b->root, parent, LL_NO_TARGET, S_ISDIR(st.st_mode) ? LL_REMOVE_DIR : LL_REMOVE_FILE);
    if (!rc) {
        unsigned int required = ll_make_right(st.st_mode);
        if (replaced) required |= S_ISDIR(replaced->st_mode) ? LL_REMOVE_DIR : LL_REMOVE_FILE;
        rc = ll_check(&b->domain, b->root, dest, LL_NO_TARGET, required);
    }
    if (!rc) rc = ll_reparent(&b->domain, b->root, parent, src, dest, st.st_mode);
    close(src);
    return rc;
}
static int64_t path_operation(struct broker *b, const struct sucrune_request *r, struct sucrune_response *out, int *send_fd) {
    const char *input = ".";
    size_t next = 0;
    int error = 0;
    if (r->operation == 50U) {
        /* fchdir resolves "." from the pinned guest dirfd. The regular and SAF
         * walkers keep their existing root, provider identity and cwd checks. */
        if (r->size || r->reserved || r->args[1] || r->args[2] || r->args[3]) return -EINVAL;
        if (host_file(b, r->args[0]) < 0) return -EBADF;
    } else {
        error = request_path(r, 0U, &input, &next);
        if (error != 0) return -error;
        if (r->operation != 38U && next != r->size) return -EINVAL;
    }
    bool exec = r->operation == SUCRUNE_BROKER_OPEN_EXEC;
    if (exec && (r->reserved || (r->args[1] & ~(int64_t)(O_CLOEXEC | O_LARGEFILE | O_NOFOLLOW)) ||
        r->args[2] || (r->args[3] != 0 && r->args[3] != 1))) return -EINVAL;
    bool optional_read = r->operation == SUCRUNE_BROKER_OPEN_READ || (exec && r->args[3]);
    if (optional_read && (r->reserved != 0U || (r->args[1] & (O_ACCMODE | O_PATH)) != O_RDONLY))
        return -EINVAL;
    bool open = r->operation == 56U || optional_read || exec;
    bool follow = r->operation == 49U || (r->operation == 79U && !(r->args[1] & AT_SYMLINK_NOFOLLOW)) ||
        (open && !(r->args[1] & O_NOFOLLOW) && (r->args[1] & (O_CREAT|O_EXCL)) != (O_CREAT|O_EXCL));
    bool mutation = r->operation == 34U || r->operation == 35U || r->operation == 38U;
    char leaf[256];
    bool must_be_directory;
    int parent = walk_parent(b, r->operation == 49U ? AT_FDCWD : r->args[0], input, follow,
                             mutation, leaf, &must_be_directory);
    if (parent < 0) return parent;
    if (r->operation == 34U) {
        /* mkdir reports EEXIST before checking permission to create a new name.
         * mkdir -p relies on this for existing ancestors outside its write scope. */
        struct stat existing;
        if (fstatat(parent, leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
            close(parent); return -EEXIST;
        }
        if (errno != ENOENT) { error = errno; close(parent); return -error; }
    }
    bool scoped_open = open && b->write_scope != SUCRUNE_WRITE_UNRESTRICTED &&
        !(r->args[1] & O_PATH) && (r->args[1] & (O_ACCMODE | O_CREAT | O_TRUNC));
    if (mutation || scoped_open) {
        int access = write_access(b, parent);
        if (access < 0) { close(parent); return access; }
    }
    if (must_be_directory && mutation && r->operation != 34U) {
        struct stat st;
        if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) < 0) { error = errno; close(parent); return -error; }
        if (!S_ISDIR(st.st_mode)) { close(parent); return -ENOTDIR; }
    }
    int64_t result = -ENOSYS;
    if (open) {
        const int allowed = O_PATH | O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_LARGEFILE | O_NONBLOCK | O_NOCTTY;
        if (r->args[1] < 0 || r->args[1] > INT32_MAX ||
            (((int)r->args[1]) & ~allowed) != 0 || (((int)r->args[1]) & O_ACCMODE) == O_ACCMODE) {
            result = -EINVAL;
        } else {
            int slot = free_slot(b);
            if (slot < 0) result = slot;
            else {
                struct file_status *state=calloc(1,sizeof(*state));
                if(state==NULL) {(void)close(parent);return -ENOMEM;}
                int lock_error=pthread_mutex_init(&state->lock,NULL);
                if(lock_error!=0) {free(state);(void)close(parent);return -lock_error;}
                atomic_init(&state->refs,1U);
                state->guest_nonblock=(int)r->args[1]&O_NONBLOCK;
                int flags = (int)r->args[1] | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
                if (must_be_directory) flags |= O_DIRECTORY;
                mode_t mode = r->args[3] == 1 ? (mode_t)r->args[2] & 0777U & ~b->creation_mask : 0600U;
                int file;
                bool no_truncate = false;
                if (flags & O_PATH) {
                    file = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC | (flags & O_DIRECTORY));
                    file = file < 0 ? -errno : sucrune_links_target_info(&b->links, file, &state->base_ino);
                } else if (b->domain.count) {
                    file = landlock_open(b, parent, leaf, flags, mode, exec, scoped_open, &no_truncate, &state->base_ino);
                } else {
                    /* Never truncate a protected alias before checking the actual FD.
                     * Refuse a read-only truncating open in the confined profile. */
                    if (scoped_open && (flags & O_TRUNC) && (flags & O_ACCMODE) == O_RDONLY) file = -EACCES;
                    else file = sucrune_links_open(&b->links, parent, leaf, scoped_open ? flags & ~O_TRUNC : flags, mode, &state->base_ino);
                    if (file >= 0 && scoped_open) {
                        int access = write_access(b, state->base_ino ? parent : file);
                        if (access == 0 && (flags & O_TRUNC) && ftruncate(file, 0) != 0) access = -errno;
                        if (access < 0) { close(file); file = access; }
                    }
                }
                if (file >= 0 && state->base_ino) {
                    int anchor = openat(parent, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                    if (anchor < 0) {
                        int saved = -errno;
                        close(file);
                        file = saved;
                    } else state->base_anchor_plus_one = anchor + 1;
                }
                if (file >= 0 && exec && input[0] == '/') {
                    int image = sucrune_exec_image_open(b->trusted_exec, input);
                    if (image >= 0) {
                        struct stat original;
                        int error_code = fstat(file, &original) < 0 ? -errno : 0;
                        if (!error_code && !S_ISREG(original.st_mode)) error_code = -EACCES;
                        if (error_code) { close(image); image = error_code; }
                        else {
                            state->image_mode = original.st_mode;
                            state->image_uid = original.st_uid;
                            state->image_gid = original.st_gid;
                        }
                    }
                    if (image != -ENOENT) { close(file); file = image; }
                }
                if (file < 0) {result = file;release_status(state);}
                else {
                    struct stat st;
                    if (fstat(file, &st) != 0 || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) &&
                        !((flags & O_PATH) && (r->args[1] & O_NOFOLLOW) && S_ISLNK(st.st_mode)))) {
                        (void)close(file);
                        release_status(state);
                        result = -EACCES;
                    } else {
                        b->files[slot] = file;
                        b->no_truncate[slot] = no_truncate;
                        b->descriptor_flags[slot] = ((int)r->args[1] & O_CLOEXEC) != 0 ? FD_CLOEXEC : 0;
                        b->status[slot] = state;
                        result = slot;
                        if (optional_read && b->profile != SUCRUNE_WORKSPACE_BUNDLED && S_ISREG(st.st_mode)) {
                            int status = fcntl(file, F_GETFL);
                            if (status >= 0 && (status & (O_ACCMODE | O_PATH)) == O_RDONLY)
                                *send_fd = file; /* The broker slot retains ownership. */
                        }
                    }
                }
            }
        }
    } else if (r->operation == 79U) {
        if (r->args[1] != 0 && r->args[1] != AT_SYMLINK_NOFOLLOW) result = -EINVAL;
        else {
            struct stat st;
            if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) result = -errno;
            else {
                result=0;
                if(S_ISLNK(st.st_mode)) {
                    ino_t base_ino = 0;
                    int target=openat(parent,leaf,O_PATH|O_NOFOLLOW|O_CLOEXEC);
                    if(target<0) result=-errno;
                    else if((target=sucrune_links_target_info(&b->links,target,&base_ino))<0) result=target;
                    else {
                        if(fstat(target,&st)!=0) result=-errno;
                        else if (base_ino) st.st_ino=base_ino;
                        (void)close(target);
                    }
                }
                if(result==0 && !S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) result=-EACCES;
                if(result==0) result=sucrune_links_stat(&b->links,&st);
                if(result==0) stat_reply(out,&st);
            }
        }
    } else if (r->operation == 49U || r->operation == 50U) {
        int directory = openat(parent, leaf, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory < 0) result = -errno;
        else if (faccessat(directory, ".", X_OK, 0) != 0) { result = -errno; (void)close(directory); }
        else { (void)close(b->cwd); b->cwd = directory; free(b->mount_cwd); b->mount_cwd=NULL; result = 0; }
    } else if (r->operation == 34U) {
        mode_t mode = r->args[3] == 1 ? (mode_t)r->args[2] & 0777U & ~b->creation_mask : 0700U;
        result = ll_check(&b->domain, b->root, parent, LL_NO_TARGET, LL_MAKE_DIR);
        if (result == 0 && mkdirat(parent, leaf, 0700) != 0) result = -errno;
        else if (result == 0) {
            int directory = openat(parent, leaf, O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC);
            result = directory < 0 ? -errno : chmod_pinned(directory, mode);
            if (directory >= 0) (void)close(directory);
            if (result < 0) (void)unlinkat(parent, leaf, AT_REMOVEDIR);
        }
    } else if (r->operation == 35U) {
        if (r->args[1] != 0 && r->args[1] != AT_REMOVEDIR) result = -EINVAL;
        else if (r->args[1] == AT_REMOVEDIR && (error = protected_directory(b, parent, leaf)) != 0) result = error;
        else {
            result = ll_check(&b->domain, b->root, parent, LL_NO_TARGET,
                              r->args[1] == AT_REMOVEDIR ? LL_REMOVE_DIR : LL_REMOVE_FILE);
            if (!result) result = sucrune_links_unlink(&b->links,parent,leaf,(int)r->args[1]);
        }
    } else if (r->operation == 38U) {
        const char *other;
        size_t end;
        error = request_path(r, next, &other, &end);
        if (error != 0 || end != r->size) result = error ? -error : -EINVAL;
        else {
            char target[256];
            bool trailing;
            int second = walk_parent(b, r->args[1], other, false, true, target, &trailing);
            if (second < 0) result = second;
            else if ((result = write_access(b, second)) < 0) close(second);
            else {
                struct stat dest;
                bool exists = fstatat(second, target, &dest, AT_SYMLINK_NOFOLLOW) == 0;
                if (!strcmp(leaf, ".") || !strcmp(target, ".")) result = -EBUSY;
                else if (exists && trailing && !S_ISDIR(dest.st_mode)) result = -ENOTDIR;
                else if (!exists && errno != ENOENT) result = -errno;
                else {
                    result = 0;
                    if (exists && S_ISDIR(dest.st_mode)) {
                        struct stat src;
                        if (fstatat(parent, leaf, &src, AT_SYMLINK_NOFOLLOW) != 0) result = -errno;
                        else if (dest.st_dev != src.st_dev || dest.st_ino != src.st_ino)
                            result = protected_directory(b, second, target);
                    } else if (trailing) {
                        struct stat src;
                        if (fstatat(parent, leaf, &src, AT_SYMLINK_NOFOLLOW) != 0) result = -errno;
                        else if (!S_ISDIR(src.st_mode)) result = -ENOTDIR;
                    }
                    if (result == 0) result = rename_rights(b, parent, leaf, second, exists ? &dest : NULL);
                    if (result == 0) result = sucrune_links_rename(&b->links,parent,leaf,second,target);
                }
                close(second);
            }
        }
    }
    (void)close(parent);
    return result;
}

static void discard_bulk_read(struct broker *b) {
    free(b->bulk_bytes);
    b->bulk_bytes = NULL;
    b->bulk_length = b->bulk_sent = 0U;
}

static int64_t bulk_read(struct broker *b, const struct sucrune_request *r, struct sucrune_response *out) {
    if (r->size != 0U || r->reserved != 0U) return -EINVAL;
    bool begin = r->operation == SUCRUNE_BROKER_BULK_READ;
    if (begin) {
        int64_t length = r->args[1], positioned = r->args[2], offset = r->args[3];
        if (length <= SUCRUNE_IO_LIMIT || length > SUCRUNE_BULK_READ_LIMIT ||
            (positioned != 0 && positioned != 1) || offset < 0 || (!positioned && offset != 0)) return -EINVAL;
        if (positioned && (offset > INT64_MAX - length || (int64_t)(off_t)(offset + length) != offset + length))
            return -EOVERFLOW;
        if (b->bulk_bytes != NULL || b->upload.bytes != NULL) return -EBUSY;
        int fd = host_file(b, r->args[0]);
        if (fd < 0) return -errno;
        struct stat st;
        if (fstat(fd, &st) != 0) return -errno;
        if (!S_ISREG(st.st_mode)) return S_ISDIR(st.st_mode) ? -EISDIR : -EINVAL;
        unsigned char *bytes = malloc((size_t)length);
        if (bytes == NULL) return -ENOMEM;
        /* One kernel I/O preserves shared-OFD position across fork sessions.
         * After the call, only the initialized prefix can be placed on the wire. */
        ssize_t got = positioned ? pread(fd, bytes, (size_t)length, (off_t)offset) :
                                   read(fd, bytes, (size_t)length);
        if (got <= 0) {
            int error = got < 0 ? errno : 0;
            free(bytes);
            return -error;
        }
        b->bulk_bytes = bytes;
        b->bulk_length = (size_t)got;
        b->bulk_sent = 0U;
    } else {
        if (r->args[0] != 0 || r->args[1] != 0 || r->args[2] != 0 || r->args[3] != 0) return -EINVAL;
        if (r->operation == SUCRUNE_BROKER_BULK_ABORT) { discard_bulk_read(b); return 0; }
        if (b->bulk_bytes == NULL) return -ENOENT;
    }
    size_t count = b->bulk_length - b->bulk_sent;
    if (count > SUCRUNE_IO_LIMIT) count = SUCRUNE_IO_LIMIT;
    int64_t result = (int64_t)(begin ? b->bulk_length : count);
    memcpy(out->data, b->bulk_bytes + b->bulk_sent, count);
    out->size = (uint32_t)count;
    b->bulk_sent += count;
    if (b->bulk_sent == b->bulk_length) discard_bulk_read(b);
    return result;
}

static int64_t bulk_write(struct broker *b,const struct sucrune_request *r) {
    if (r->reserved!=0U) return -EINVAL;
    if (r->operation==SUCRUNE_BROKER_BULK_WRITE) {
        int64_t count=r->args[1],positioned=r->args[2],offset=r->args[3];
        unsigned int limit=b->profile==SUCRUNE_WORKSPACE_BUILD ? SUCRUNE_BUILD_BULK_WRITE_LIMIT : SUCRUNE_BULK_WRITE_LIMIT;
        if (r->size || count<=SUCRUNE_IO_LIMIT || count>limit ||
            (positioned!=0 && positioned!=1) || offset<0 || (!positioned && offset!=0)) return -EINVAL;
        if (positioned && (offset>INT64_MAX-count || (int64_t)(off_t)(offset+count)!=offset+count)) return -EOVERFLOW;
        if (b->upload.bytes!=NULL || b->bulk_bytes!=NULL) return -EBUSY;
        int fd=host_file(b,r->args[0]);
        if(fd<0) return -errno;
        struct stat st;
        if(fstat(fd,&st)!=0) return -errno;
        if(!S_ISREG(st.st_mode)) return S_ISDIR(st.st_mode) ? -EISDIR : -EINVAL;
        int flags=fcntl(fd,F_GETFL);
        if(flags<0) return -errno;
        if((flags&O_ACCMODE)==O_RDONLY || (flags&O_PATH)!=0) return -EBADF;
        b->upload.bytes=malloc((size_t)count);
        if(b->upload.bytes==NULL) return -ENOMEM;
        b->upload.length=(size_t)count;
        b->upload.slot=(int)r->args[0];
        b->upload.offset=positioned ? (off_t)offset : (off_t)-1;
        return 0;
    }
    if(r->args[1] || r->args[2] || r->args[3]) return -EINVAL;
    if(r->operation==SUCRUNE_BROKER_BULK_PUSH) {
        if(b->upload.bytes==NULL) return -ENOENT;
        if(r->args[0]!=(int64_t)b->upload.received || r->size==0U || r->size>SUCRUNE_IO_LIMIT ||
            r->size>b->upload.length-b->upload.received) return -EINVAL;
        memcpy(b->upload.bytes+b->upload.received,r->data,r->size);
        b->upload.received+=r->size;
        return 0;
    }
    if(r->args[0] || r->size) return -EINVAL;
    if(r->operation==SUCRUNE_BROKER_BULK_DROP) {discard_upload(b);return 0;}
    if(b->upload.bytes==NULL) return -ENOENT;
    if(b->upload.received!=b->upload.length) return -EINVAL;
    int fd=b->files[b->upload.slot];
    ssize_t written=b->upload.offset==(off_t)-1 ? write(fd,b->upload.bytes,b->upload.length)
        : pwrite(fd,b->upload.bytes,b->upload.length,b->upload.offset);
    int64_t result=written<0 ? -errno : written;
    discard_upload(b);
    return result;
}

static struct ll_ruleset *ruleset_at(struct broker *b, int64_t slot) {
    return slot >= 3 && slot < FILE_SLOTS ? b->rulesets[slot] : NULL;
}
static int wrong_ruleset(struct broker *b, int64_t slot) {
    return host_file(b, slot) < 0 ? -EBADF : -EBADFD;
}
static int landlock_operation(struct broker *b, const struct sucrune_request *r) {
    if (b->profile == SUCRUNE_WORKSPACE_BUNDLED) return -ENOSYS;
    if (r->size || r->reserved) return -EINVAL;
    const int64_t *a = r->args;
    switch (r->operation) {
    case 167:
        if (a[2] || a[3]) return -EINVAL;
        if (a[0] == 39 && !a[1]) return b->domain.no_new_privs ? 1 : 0;
        if (a[0] != 38 || a[1] != 1) return -EINVAL;
        b->domain.no_new_privs = true;
        return 0;
    case 444: {
        if (a[3]) return -EINVAL;
        if (!a[0] && !a[1] && a[2] == 1) return 3;
        if (a[2] || a[1] < 8) return -EINVAL;
        if (a[1] > 4096) return -E2BIG;
        int slot = free_slot(b);
        if (slot < 0) return slot;
        int err = ll_create((uint64_t)a[0], &b->rulesets[slot]);
        if (err) return err;
        b->descriptor_flags[slot] = FD_CLOEXEC;
        return slot;
    }
    case 445: {
        struct ll_ruleset *set = ruleset_at(b, a[0]);
        if (!set) return wrong_ruleset(b, a[0]);
        if (a[1] != 1) return -EINVAL;
        int fd;
        if (a[3] == LL_DEV_NULL) fd = LL_DEV_NULL;
        else {
            fd = host_file(b, a[3]);
            if (fd < 0) return -EBADF;
            if (b->status[a[3]]->base_anchor_plus_one) {
                fd = b->status[a[3]]->base_anchor_plus_one - 1;
                /* A file-specific write rule must keep matching after its
                 * first writable open replaces the project marker. */
                if (a[2] & (LL_WRITE_FILE | LL_TRUNCATE)) {
                    int private_target = private_fd_target(b, a[3]);
                    if (private_target >= 0) {
                        int rc = ll_add(set, (uint64_t)a[2], private_target);
                        close(private_target);
                        return rc;
                    }
                    if (private_target != -EACCES) return private_target;
                }
            }
            struct mount_file *m=mounted_file(b,a[3]);
            if (m) {
                if (*m->path) return -EOPNOTSUPP;
                fd=b->family->mount_anchor;
            }
        }
        return ll_add(set, (uint64_t)a[2], fd);
    }
    case 446: {
        if (a[1] || a[2] || a[3]) return -EINVAL;
        if (!b->domain.no_new_privs) return -EPERM;
        struct ll_ruleset *set = ruleset_at(b, a[0]);
        return set ? ll_restrict(&b->domain, set) : wrong_ruleset(b, a[0]);
    }
    case SUCRUNE_BROKER_LL_SPECIAL:
        if ((a[0] != LL_DEV_NULL && a[0] != LL_OTHER_SPECIAL) ||
            ((uint64_t)a[1] & ~(uint64_t)LL_ALL) || a[2] || a[3]) return -EINVAL;
        return ll_check(&b->domain, b->root, b->root, (int)a[0], (unsigned int)a[1]);
    default: return -ENOSYS;
    }
}
/* Device-wide aggregate counters only. Never forward the Android mount table,
 * an arbitrary proc path, or a process-specific proc record. */
static int system_contents(struct broker *b,const struct sucrune_request *r,struct sucrune_response *out) {
    if(b->profile==SUCRUNE_WORKSPACE_BUNDLED) return -ENOSYS;
    if(r->size || r->reserved || r->args[1] || r->args[2] || r->args[3]) return -EINVAL;
    if(r->args[0]==SUCRUNE_SYS_MOUNTS) {
        int n=snprintf((char *)out->data,sizeof(out->data),"sucrune / sucrunefs %s 0 0\nproc /proc proc ro 0 0\n%s",
            b->write_scope==SUCRUNE_WRITE_READ_ONLY ? "ro" : "rw",
            b->family->mount.stat ? (b->write_scope==SUCRUNE_WRITE_READ_ONLY ?
            "documents /workspace saf ro 0 0\n" : "documents /workspace saf rw 0 0\n") : "");
        out->size=(uint32_t)n; return 0;
    }
    const char *path;
    if(r->args[0]==SUCRUNE_SYS_MEMINFO) path="/proc/meminfo";
    else if(r->args[0]==SUCRUNE_SYS_UPTIME) path="/proc/uptime";
    else return -EINVAL;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd>=0) {
        size_t used=0;
        while(used<sizeof(out->data)) {
            ssize_t n=read(fd,out->data+used,sizeof(out->data)-used);
            if(n<0 && errno==EINTR) continue;
            if(n<0) { int err=errno; close(fd); return -err; }
            if(!n) break;
            used+=(size_t)n;
        }
        close(fd);
        while(used && out->data[used-1U]!='\n') used--;
        if(!used) return -EIO;
        out->size=(uint32_t)used; return 0;
    }
    if(r->args[0]!=SUCRUNE_SYS_MEMINFO) return -errno;
    /* Some Android releases deny /proc/meminfo; sysinfo still supplies
     * these counters. Do not synthesize MemAvailable or page-cache totals. */
    struct sysinfo info;
    if(sysinfo(&info)<0) return -errno;
    unsigned long long unit=info.mem_unit;
    int n=snprintf((char *)out->data,sizeof(out->data),
        "MemTotal: %llu kB\nMemFree: %llu kB\nBuffers: %llu kB\nShmem: %llu kB\nSwapTotal: %llu kB\nSwapFree: %llu kB\n",
        info.totalram*unit/1024,info.freeram*unit/1024,info.bufferram*unit/1024,
        info.sharedram*unit/1024,info.totalswap*unit/1024,info.freeswap*unit/1024);
    out->size=(uint32_t)n; return 0;
}
static int open_socket_table(struct broker *b, const struct sucrune_request *r) {
    if (b->profile == SUCRUNE_WORKSPACE_BUNDLED) return -ENOSYS;
    if (r->reserved || r->size || r->args[0] < SUCRUNE_SYS_TCP || r->args[0] > SUCRUNE_SYS_UDP6 ||
        (r->args[1] != 0 && r->args[1] != O_CLOEXEC) || r->args[2] < 0 || r->args[2] > UINT32_MAX || r->args[3]) return -EINVAL;
    int slot = free_slot(b);
    if (slot < 0) return slot;
    int fd = sucrune_network_proc_open(&b->network, (int)r->args[0], (uint32_t)r->args[2]);
    if (fd < 0) return fd;
    struct file_status *state = calloc(1, sizeof(*state));
    if (!state) { close(fd); return -ENOMEM; }
    int error = pthread_mutex_init(&state->lock, NULL);
    if (error) { free(state); close(fd); return -error; }
    atomic_init(&state->refs, 1U);
    b->files[slot] = fd;
    b->status[slot] = state;
    state->proc_table = (int)r->args[0];
    b->descriptor_flags[slot] = r->args[1] ? FD_CLOEXEC : 0;
    return slot;
}
static int filesystem_info(struct broker *b,const struct sucrune_request *r,struct sucrune_response *out) {
    if(b->profile==SUCRUNE_WORKSPACE_BUNDLED) return -ENOSYS;
    if(r->reserved || r->args[1] || r->args[2] || r->args[3]) return -EINVAL;
    int pin;
    if(r->operation==43) {
        const char *path; size_t end;
        int error=request_path(r,0,&path,&end);
        if(error || end!=r->size || r->args[0]!=AT_FDCWD) return error ? -error : -EINVAL;
        pin=query_target(b,AT_FDCWD,path,false,true,false);
        if(pin<0) return pin;
    } else {
        if(r->size) return -EINVAL;
        pin=host_file(b,r->args[0]);
        if(pin<0) return -errno;
    }
    struct statfs volume={0};
    _Static_assert(sizeof(volume)==120 && offsetof(struct statfs,f_flags)==80,"Linux 64-bit statfs ABI");
    int rc = r->operation == 44 && b->status[r->args[0]]->proc_table
        ? statfs("/proc", &volume) : fstatfs(pin, &volume);
    if (rc < 0) rc = -errno;
    if(r->operation==43) close(pin);
    if(rc<0) return rc;
    memcpy(out->data,&volume,sizeof(volume)); out->size=sizeof(volume); return 0;
}
#include "workspace_mount.inc"
static void dispatch(struct broker *b, const struct sucrune_request *r, struct sucrune_response *out, int *send_fd) {
    out->magic = SUCRUNE_BROKER_MAGIC;
    out->size = 0;
    out->result = -ENOSYS;
    if (b->family->mount.stat && mount_fd_operation(b,r,out)) return;
    switch (r->operation) {
        case SUCRUNE_BROKER_PROC_CONTENTS: out->result=system_contents(b,r,out); break;
        case SUCRUNE_BROKER_PROC_NET_OPEN: out->result=open_socket_table(b,r); break;
        case 43: case 44: out->result=filesystem_info(b,r,out); break;
        case 167: case 444: case 445: case 446: case SUCRUNE_BROKER_LL_SPECIAL:
            out->result = landlock_operation(b, r); break;
        case SUCRUNE_BROKER_BULK_WRITE: case SUCRUNE_BROKER_BULK_PUSH:
        case SUCRUNE_BROKER_BULK_COMMIT: case SUCRUNE_BROKER_BULK_DROP:
            out->result=bulk_write(b,r);
            break;
        case SUCRUNE_BROKER_BULK_READ: case SUCRUNE_BROKER_BULK_NEXT: case SUCRUNE_BROKER_BULK_ABORT:
            out->result = bulk_read(b, r, out);
            break;
        case SUCRUNE_BROKER_EXEC_COMMIT:
            if (r->size != 0U || r->reserved != 0U || r->args[0] != 0 ||
                r->args[1] != 0 || r->args[2] != 0 || r->args[3] != 0) {
                out->result = -EINVAL;
                break;
            }
            /* Keep the broker, cwd and every non-CLOEXEC open description.
             * close() must not be retried: on Linux an interrupted close has
             * already released the descriptor number. */
            for (int slot = 3; slot < FILE_SLOTS; slot++) {
                if (b->rulesets[slot]) {
                    if (b->descriptor_flags[slot] & FD_CLOEXEC) (void)close_file(b, slot);
                    continue;
                }
                if (b->files[slot] < 0) continue;
                bool closing = (b->descriptor_flags[slot] & FD_CLOEXEC) != 0;
                if (closing || b->exec_record_close[slot]) sucrune_record_close(&b->record_locks,b->files[slot]);
                b->exec_record_close[slot]=0;
                if (closing) (void)close_file(b,slot);
            }
            sucrune_pty_broker_exec(&b->ptys);
            discard_bulk_read(b);
            discard_upload(b);
            out->result = 0;
            break;
        case 56: case SUCRUNE_BROKER_OPEN_READ: case SUCRUNE_BROKER_OPEN_EXEC: case 49: case 50: case 34: case 35: case 38: case 79:
            out->result = path_operation(b, r, out, send_fd); break;
        case 36: out->result = symlink_project(b, r); break;
        case SUCRUNE_BROKER_LINKAT: out->result=link_project_file(b,r);break;
        case 53: out->result = chmod_project_path(b, r); break;
        case SUCRUNE_BROKER_UTIMENSAT: out->result = utimens_project(b, r); break;
        case SUCRUNE_BROKER_UMASK:
            if (r->size || r->reserved || r->args[1] || r->args[2] || r->args[3]) out->result = -EINVAL;
            else {
                out->result = (int64_t)b->creation_mask;
                b->creation_mask = (mode_t)r->args[0] & 0777U;
            }
            break;
        case SUCRUNE_BROKER_FACCESSAT: case SUCRUNE_BROKER_FACCESSAT2: case SUCRUNE_BROKER_READLINKAT:
            out->result = query_operation(b, r, out); break;
        case 80: {
            int file = host_file(b, r->args[0]);
            struct stat st;
            if (file < 0 || fstat(file, &st) != 0) out->result = -errno;
            else {
                const struct file_status *state = b->status[r->args[0]];
                if (state->proc_table) {
                    struct sucrune_arm64_stat metadata;
                    sucrune_proc_system_stat(state->proc_table, &metadata);
                    memcpy(out->data, &metadata, sizeof(metadata));
                    out->size = sizeof(metadata);
                    out->result = 0;
                    break;
                }
                if (state->image_mode) {
                    st.st_mode = state->image_mode;
                    st.st_uid = state->image_uid;
                    st.st_gid = state->image_gid;
                    out->result = 0;
                } else out->result = sucrune_links_stat(&b->links, &st);
                if (state->base_ino) {
                    st.st_ino = state->base_ino;
                    if (state->private_pin_plus_one) {
                        struct stat metadata;
                        if (fstat(state->private_pin_plus_one-1,&metadata)) out->result=-errno;
                        else {
                            st.st_mode=metadata.st_mode;
                            st.st_atim=metadata.st_atim; st.st_mtim=metadata.st_mtim; st.st_ctim=metadata.st_ctim;
                        }
                    }
                }
                if (!out->result) stat_reply(out, &st);
            }
            break;
        }
        case SUCRUNE_BROKER_FSYNC: case SUCRUNE_BROKER_FDATASYNC: {
            int file = host_file(b, r->args[0]);
            if (file < 0) out->result = -errno;
            else if (r->size != 0U || r->reserved != 0U || r->args[1] != 0 ||
                r->args[2] != 0 || r->args[3] != 0) out->result = -EINVAL;
            else {
                int synced = r->operation == SUCRUNE_BROKER_FSYNC ? fsync(file) : fdatasync(file);
                out->result = synced == 0 ? 0 : -errno;
            }
            break;
        }
        case SUCRUNE_BROKER_RECORD_LOCK: {
            int file=host_file(b,r->args[0]);
            struct sucrune_record_lock range;
            _Static_assert(sizeof(range)==32, "ARM64 struct flock size");
            if (file<0) out->result=-errno;
            else if (b->status[r->args[0]]->base_ino) out->result = -EOPNOTSUPP;
            else if (r->size!=sizeof(range) || r->reserved || r->args[2]<=0 || r->args[2]>INT_MAX ||
                     r->args[3] || (r->args[1]!=F_GETLK && r->args[1]!=F_SETLK)) out->result=-EINVAL;
            else {
                memcpy(&range,r->data,sizeof(range));
                out->result=sucrune_record_lock_op(&b->record_locks,file,(int)r->args[1],(int)r->args[2],&range);
                if ((out->result==0 && r->args[1]==F_GETLK) || (out->result==-EAGAIN && r->args[1]==F_SETLK)) {
                    memcpy(out->data,&range,sizeof(range));out->size=sizeof(range);
                }
            }
            break;
        }
        case SUCRUNE_BROKER_FLOCK: {
            int file = host_file(b, r->args[0]);
            if (file < 0) out->result = -errno;
            else if (b->status[r->args[0]]->base_ino) out->result = -EOPNOTSUPP;
            else if (r->size != 0U || r->reserved != 0U || r->args[2] != 0 || r->args[3] != 0 ||
                (r->args[1] != LOCK_UN && r->args[1] != (LOCK_UN | LOCK_NB) &&
                 r->args[1] != (LOCK_SH | LOCK_NB) && r->args[1] != (LOCK_EX | LOCK_NB))) {
                /* Blocking locks must not stall this project's broker or
                 * hold the execution's cleanup lease indefinitely. */
                out->result = (r->args[1] == LOCK_SH || r->args[1] == LOCK_EX) ? -EOPNOTSUPP : -EINVAL;
            } else out->result = flock(file, (int)r->args[1]) == 0 ? 0 : -errno;
            break;
        }
        case 25: {
            if (ruleset_at(b, r->args[0])) {
                int *flags = &b->descriptor_flags[r->args[0]];
                if (r->args[1] == F_GETFD) out->result = *flags;
                else if (r->args[1] == F_SETFD && !(r->args[2] & ~FD_CLOEXEC)) {
                    *flags = (int)r->args[2]; out->result = 0;
                } else if (r->args[1] == F_GETFL) out->result = O_RDWR;
                else out->result = -EINVAL;
                break;
            }
            int file = host_file(b, r->args[0]);
            if (file < 0) out->result = -errno;
            else if (r->args[1] == F_GETFD) out->result = b->descriptor_flags[r->args[0]];
            else if (r->args[1] == F_SETFD && (r->args[2] & ~FD_CLOEXEC) == 0 && (r->args[3]==0 || r->args[3]==1)) {
                b->exec_record_close[r->args[0]]=(unsigned char)r->args[3];
                b->descriptor_flags[r->args[0]] = (int)r->args[2]; out->result = 0;
            }
            else if (r->args[1] == F_GETFL) {
                struct file_status *state=b->status[r->args[0]];
                (void)pthread_mutex_lock(&state->lock);
                int flags = fcntl(file, F_GETFL);
                /* The kernel can report extra bits, including a large-file bit
                 * even when the host libc defines O_LARGEFILE as zero. */
                const int visible = O_ACCMODE | O_APPEND | O_DIRECTORY | O_NOFOLLOW | O_PATH | O_LARGEFILE;
                out->result = flags < 0 ? -errno : (flags & visible) | state->guest_nonblock;
                (void)pthread_mutex_unlock(&state->lock);
            } else if (r->args[1] == F_SETFL) {
                /* Append is passed through; nonblock is virtualized for these
                 * regular/directory descriptions. Access/open-time bits remain
                 * unchanged. Never clear the manager's nonblocking safeguard. */
                const int allowed = O_APPEND | O_NONBLOCK | O_ACCMODE | O_LARGEFILE | O_NOFOLLOW |
                    O_DIRECTORY | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC | O_NOCTTY;
                if (r->args[2] < 0 || r->args[2] > INT32_MAX ||
                    (((int)r->args[2]) & ~allowed) != 0) out->result = -EINVAL;
                else {
                    struct file_status *state=b->status[r->args[0]];
                    (void)pthread_mutex_lock(&state->lock);
                    int flags = fcntl(file, F_GETFL);
                    if (flags < 0) out->result = -errno;
                    else {
                        flags = (flags & ~O_APPEND) | ((int)r->args[2] & O_APPEND) | O_NONBLOCK;
                        if (fcntl(file, F_SETFL, flags) != 0) out->result = -errno;
                        else {
                            state->guest_nonblock = (int)r->args[2] & O_NONBLOCK;
                            out->result = 0;
                        }
                    }
                    (void)pthread_mutex_unlock(&state->lock);
                }
            } else out->result = -EINVAL;
            break;
        }
        case 17:
            out->result = current_directory(b, out);
            if (out->result >= 0 && out->result > r->args[0]) { out->size = 0; out->result = -ERANGE; }
            break;
        case 46: {
            int file = host_file(b, r->args[0]);
            struct stat st;
            if (file < 0) out->result = -errno;
            else if (r->size != 0U || r->reserved != 0U || r->args[1] < 0 ||
                r->args[2] != 0 || r->args[3] != 0) out->result = -EINVAL;
            else if (r->args[1] > SUCRUNE_TRUNCATE_LIMIT) out->result = -EFBIG;
            else if (fstat(file, &st) != 0) out->result = -errno;
            else if (!S_ISREG(st.st_mode)) out->result = -EINVAL;
            else if (b->no_truncate[r->args[0]]) out->result = -EACCES;
            else out->result = ftruncate(file, (off_t)r->args[1]) == 0 ? 0 : -errno;
            break;
        }
        case 47: { /* fallocate(fd, 0, offset, length) */
            int file = host_file(b, r->args[0]);
            int64_t offset = r->args[2], length = r->args[3];
            struct stat st;
            if (file < 0) { out->result = -errno; break; }
            if (r->size != 0U || r->reserved != 0U || offset < 0 || length <= 0) {
                out->result = -EINVAL; break;
            }
            if (r->args[1] != 0) { out->result = -EOPNOTSUPP; break; }
            if (offset > SUCRUNE_TRUNCATE_LIMIT || length > SUCRUNE_TRUNCATE_LIMIT - offset) {
                out->result = -EFBIG; break;
            }
            int flags = fcntl(file, F_GETFL);
            if (flags < 0 || fstat(file, &st) != 0) out->result = -errno;
            else if ((flags & O_PATH) || (flags & O_ACCMODE) == O_RDONLY) out->result = -EBADF;
            else if (!S_ISREG(st.st_mode)) out->result = -ENODEV;
            else out->result = -posix_fallocate(file, (off_t)offset, (off_t)length);
            break;
        }
        case 52: {
            int file = host_file(b, r->args[0]);
            if (file < 0) out->result = -errno;
            else if (r->size != 0U || r->reserved != 0U || r->args[1] < 0 ||
                (r->args[1] & ~INT64_C(0777)) != 0 || r->args[2] != 0 || r->args[3] != 0)
                out->result = -EINVAL;
            else if (b->status[r->args[0]]->proc_table) out->result = -EROFS;
            else if (b->status[r->args[0]]->base_ino) {
                int flags = fcntl(file, F_GETFL);
                if (flags < 0) out->result = -errno;
                else if (flags & O_PATH) out->result = -EBADF;
                else {
                    int target = private_fd_target(b, r->args[0]);
                    out->result = target < 0 ? target : chmod_pinned(target, (mode_t)r->args[1]);
                    if (target >= 0) close(target);
                }
            } else if ((out->result = write_access(b, file)) == 0)
                out->result = fchmod(file, (mode_t)r->args[1]) == 0 ? 0 : -errno;
            break;
        }
        case SUCRUNE_BROKER_RECORD_CLOSE: case SUCRUNE_BROKER_PRIVATE_CLOSE: case 57: {
            if (ruleset_at(b, r->args[0])) {
                out->result = r->operation == SUCRUNE_BROKER_RECORD_CLOSE ? 0 : close_file(b, (int)r->args[0]);
                break;
            }
            int file = host_file(b, r->args[0]);
            if (file < 0) out->result = -errno;
            else {
                if (r->operation!=SUCRUNE_BROKER_PRIVATE_CLOSE) sucrune_record_close(&b->record_locks,file);
                out->result=r->operation==SUCRUNE_BROKER_RECORD_CLOSE ? 0 : close_file(b,(int)r->args[0]);
            }
            break;
        }
        case 63: case 64: case 61: {
            int file = host_file(b, r->args[0]);
            if (file < 0) { out->result = -errno; break; }
            if (r->args[1] < 0 || r->args[1] > SUCRUNE_IO_LIMIT) { out->result = -EINVAL; break; }
            size_t count = (size_t)r->args[1];
            ssize_t result;
            if (r->operation == 64U) {
                if (r->size != count) { out->result = -EINVAL; break; }
                result = write(file, r->data, count);
            } else if (r->operation == 63U) result = read(file, out->data, count);
            else result = (ssize_t)syscall(SYS_getdents64, file, out->data, count);
            out->result = result < 0 ? -errno : result;
            if(result>0 && r->operation==61U) {
                int validated=sucrune_links_dirents(&b->links,file,out->data,(size_t)result);
                if(validated<0) {out->result=validated;break;}
            }
            if (result >= 0 && r->operation != 64U) out->size = (uint32_t)result;
            break;
        }
        case 62: {
            int file = host_file(b, r->args[0]);
            if (file < 0) out->result = -errno;
            else { off_t result = lseek(file, (off_t)r->args[1], (int)r->args[2]); out->result = result < 0 ? -errno : result; }
            break;
        }
        case SUCRUNE_BROKER_SENDFILE: {
            if (r->size != 0U || r->reserved != 0U || r->args[2] < 0 || r->args[3] < -1) {
                out->result = -EINVAL; break;
            }
            int output = host_file(b, r->args[0]);
            if (output < 0) { out->result = -errno; break; }
            int input = host_file(b, r->args[1]);
            if (input < 0) { out->result = -errno; break; }
            struct stat src, dst;
            if (fstat(input, &src) < 0 || fstat(output, &dst) < 0) { out->result = -errno; break; }
            if (!S_ISREG(src.st_mode) || !S_ISREG(dst.st_mode)) { out->result = -EINVAL; break; }
            off_t offset = (off_t)r->args[3];
            if ((int64_t)offset != r->args[3]) { out->result = -EOVERFLOW; break; }
            /* Bound a single manager operation. Linux permits short transfers;
             * the shared input/output OFD offsets are advanced by the kernel. */
            size_t count = (size_t)(r->args[2] > SUCRUNE_BULK_READ_LIMIT ? SUCRUNE_BULK_READ_LIMIT : r->args[2]);
            ssize_t sent = sendfile(output, input, offset == (off_t)-1 ? NULL : &offset, count);
            out->result = sent < 0 ? -errno : sent;
            break;
        }
        case SUCRUNE_BROKER_PREAD64: case SUCRUNE_BROKER_PWRITE64: {
            int file = host_file(b, r->args[0]);
            if (file < 0) { out->result = -errno; break; }
            if (r->args[1] < 0 || r->args[1] > SUCRUNE_IO_LIMIT || r->args[2] < 0 ||
                r->args[3] != 0 || r->reserved != 0U) { out->result = -EINVAL; break; }
            size_t count = (size_t)r->args[1];
            bool writing = r->operation == SUCRUNE_BROKER_PWRITE64;
            if (r->size != (writing ? count : 0U)) { out->result = -EINVAL; break; }
            if (r->args[2] > INT64_MAX - r->args[1]) { out->result = -EOVERFLOW; break; }
            off_t offset = (off_t)r->args[2];
            off_t end = (off_t)(r->args[2] + r->args[1]);
            if ((int64_t)offset != r->args[2] || (int64_t)end != r->args[2] + r->args[1]) {
                out->result = -EOVERFLOW; break;
            }
            ssize_t result = writing ? pwrite(file, r->data, count, offset) :
                                       pread(file, out->data, count, offset);
            out->result = result < 0 ? -errno : result;
            if (result >= 0 && !writing) out->size = (uint32_t)result;
            break;
        }
        default: break;
    }
}

static void *serve(void *argument);
static int start_server(struct broker *b) {
    pthread_attr_t attributes;
    int error=pthread_attr_init(&attributes);
    if(error!=0) return -error;
    error=pthread_attr_setdetachstate(&attributes,PTHREAD_CREATE_DETACHED);
    if(error==0) {pthread_t thread;error=pthread_create(&thread,&attributes,serve,b);}
    (void)pthread_attr_destroy(&attributes);
    return -error;
}
static int setup_network(struct broker *b,int policy) {
    int result=sucrune_network_init(&b->network,policy);
    if(result!=0) return result;
    b->network.total_resource_limit=b->resource_limit;
    b->network.build_profile=b->profile==SUCRUNE_WORKSPACE_BUILD;
    if(policy==SUCRUNE_NETWORK_OUTBOUND) {
        struct sucrune_dns_config config={b->network_handle,5000U};
        uint16_t port=0;
        result=sucrune_dns_proxy_start(&config,NULL,&b->dns);
        if(result==0) result=sucrune_dns_proxy_endpoint(b->dns,&port);
        struct sucrune_network_hooks hooks={b,select_outbound_network,add_dns_client,remove_dns_client,port};
        if(result==0) result=sucrune_network_set_hooks(&b->network,&hooks);
    }
    if(result==0 && b->profile!=SUCRUNE_WORKSPACE_BUNDLED) result=sucrune_network_attach_workspace(&b->network,b->root);
    return result;
}
static void destroy_server(struct broker *b) {
    discard_bulk_read(b);
    discard_upload(b);
    sucrune_record_destroy(&b->record_locks);
    sucrune_links_destroy(&b->links);
    sucrune_network_destroy(&b->network);
    sucrune_pty_broker_destroy(&b->ptys);
    for(int i=3;i<FILE_SLOTS;i++) if(b->files[i]>=0 || b->rulesets[i]) (void)close_file(b,i);
    ll_release(&b->domain);
    sucrune_exec_image_release(b->trusted_exec);
    if(b->root>=0) (void)close(b->root);
    if(b->cwd>=0) (void)close(b->cwd);
    free(b->mount_cwd);
    if(b->socket>=0) (void)close(b->socket);
    stop_dns(b);
    release_family(b->family);
    if(b->completion>=0) (void)close(b->completion);
    free(b);
}
static int fork_session(struct broker *parent,const struct sucrune_request *request) {
    if(request->size!=0U || request->reserved!=0U || request->args[0]!=0 || request->args[1]!=0 ||
       request->args[2]!=0 || request->args[3]!=0) return -EINVAL;
    unsigned int count=atomic_load_explicit(&parent->family->sessions,memory_order_acquire);
    do {if(count>=17U) return -EAGAIN;}
    while(!atomic_compare_exchange_weak_explicit(&parent->family->sessions,&count,count+1U,memory_order_acq_rel,memory_order_acquire));
    struct broker *child=calloc(1,sizeof(*child));
    if(child==NULL) {release_family(parent->family);return -ENOMEM;}
    child->family=parent->family;child->socket=-1;child->root=-1;child->completion=-1;child->cwd=-1;
    child->links.parent=-1;child->links.store=-1;child->links.base=-1;
    for(int i=0;i<FILE_SLOTS;i++) child->files[i]=-1;
    (void)sucrune_network_init(&child->network,SUCRUNE_NETWORK_NONE);
    child->network_handle=parent->network_handle;
    child->creation_mask=parent->creation_mask;
    child->resource_limit=parent->resource_limit;
    child->profile=parent->profile;
    child->write_scope=parent->write_scope;
    child->trusted_exec = parent->trusted_exec;
    sucrune_exec_image_retain(child->trusted_exec);
    ll_inherit(&child->domain, &parent->domain);
    for (int i = 3; i < FILE_SLOTS; i++) if (parent->rulesets[i]) {
        child->rulesets[i] = parent->rulesets[i];
        ll_hold(child->rulesets[i]);
        child->descriptor_flags[i] = parent->descriptor_flags[i];
    }
    sucrune_pty_broker_fork(&child->ptys, &parent->ptys);
    int pair[2]={-1,-1};
    int result=0;
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair)!=0) {result=-errno;goto failed;}
    child->socket=pair[0];
    child->root=fcntl(parent->root,F_DUPFD_CLOEXEC,3);
    if(child->root<0) {result=-errno;goto failed;}
    child->cwd=fcntl(parent->cwd,F_DUPFD_CLOEXEC,3);
    if(child->cwd<0) {result=-errno;goto failed;}
    if(parent->mount_cwd && !(child->mount_cwd=strdup(parent->mount_cwd))) {result=-ENOMEM;goto failed;}
    result=sucrune_links_clone(&child->links,&parent->links);
    if(result<0) goto failed;
    child->completion=fcntl(parent->completion,F_DUPFD_CLOEXEC,3);
    if(child->completion<0) {result=-errno;goto failed;}
    for(int i=3;i<FILE_SLOTS;i++) if(parent->files[i]>=0) {
        int dupfd=fcntl(parent->files[i],F_DUPFD_CLOEXEC,3);
        if(dupfd<0) {result=-errno;goto failed;}
        child->no_truncate[i] = parent->no_truncate[i];
        child->files[i]=dupfd;child->descriptor_flags[i]=parent->descriptor_flags[i];
        child->status[i]=parent->status[i];
        (void)atomic_fetch_add_explicit(&child->status[i]->refs,1U,memory_order_relaxed);
    }
    result=setup_network(child,parent->network.policy);
    if(result==0) result=sucrune_network_fork_connected(&child->network,&parent->network);
    if(result==0) result=start_server(child);
    if(result==0) return pair[1];
failed:
    if(pair[1]>=0) (void)close(pair[1]);
    destroy_server(child);
    return result;
}
static void *serve(void *argument) {
    struct broker *b = argument;
    struct sucrune_request request;
    struct sucrune_response response;
    for (;;) {
        if (sucrune_network_wait_control(&b->network, b->socket) != 0) break;
        if (sucrune_broker_receive_request(b->socket, &request, -1) != 0) break;
        int send_fd = -1;
        if(request.operation==SUCRUNE_BROKER_FORK_SESSION) {
            int session=fork_session(b,&request);
            response=(struct sucrune_response){.magic=SUCRUNE_BROKER_MAGIC,.result=session<0 ? session : 0};
            if(session>=0) send_fd=session;
        } else if (request.operation == SUCRUNE_BROKER_MAP_FILE) {
            int fd = shared_mapping_file(b, &request);
            response = (struct sucrune_response){.magic = SUCRUNE_BROKER_MAGIC, .result = fd < 0 ? fd : 0};
            if (fd >= 0) send_fd = fd; /* the file table owns this descriptor */
        } else if ((request.operation == SUCRUNE_PTY_MASTER_OPEN || request.operation == SUCRUNE_PTY_SLAVE_OPEN) &&
                file_and_pty_count(b) + b->network.count >= b->resource_limit)
            response = (struct sucrune_response){.magic = SUCRUNE_BROKER_MAGIC, .result = -EMFILE};
        else if (sucrune_pty_broker_claims(&request))
            sucrune_pty_broker_dispatch(&b->ptys, &request, &response, &send_fd, stat_reply);
        else if (sucrune_net_operation(request.operation))
            sucrune_network_dispatch(&b->network, file_and_pty_count(b), &request, &response, &send_fd);
        else {
            int lock=0;
            switch(request.operation) {
            case 34:case 35:case 36:case 37:case 38:case 52:case 53:case 445:case SUCRUNE_BROKER_UTIMENSAT:lock=LOCK_EX;break;
            case 56:case SUCRUNE_BROKER_OPEN_READ:case SUCRUNE_BROKER_OPEN_EXEC:lock=(request.args[1]&(O_CREAT|O_ACCMODE|O_TRUNC))!=0 ? LOCK_EX : LOCK_SH;break;
            case 17:case 43:case 48:case 49:case 50:case 61:case 78:case 79:case 80:case 439:lock=LOCK_SH;break;
            default:break;
            }
            if(lock && flock(b->links.parent,lock)!=0)
                response=(struct sucrune_response){.magic=SUCRUNE_BROKER_MAGIC,.result=-errno};
            else {
                dispatch(b,&request,&response,&send_fd);
                if (response.result==MOUNT_TARGET)
                    response.result=mount_path_operation(b,&request,&response,&send_fd);
                if(lock) (void)flock(b->links.parent,LOCK_UN);
            }
        }
        int sent=sucrune_broker_send_response(b->socket, request.operation, &response, send_fd, 5000);
        if((request.operation==SUCRUNE_BROKER_FORK_SESSION || request.operation==SUCRUNE_PTY_CONTROL_MASTER ||
            request.operation==SUCRUNE_NET_ECHO_SOCKET) && send_fd>=0) (void)close(send_fd);
        if(sent!=0) break;
    }
    destroy_server(b);
    return NULL;
}

static int create_broker(const char *workspace, int *completion, int network_policy,
                                    uint64_t network_handle, enum sucrune_workspace_profile profile,
                                    enum sucrune_write_scope scope, struct sucrune_exec_image *image,
                                    const struct sucrune_guest_directory *mount, bool *consumed) {
    if (workspace == NULL || workspace[0] != '/' || completion == NULL) return -EINVAL;
    *completion = -1;
    if (scope != SUCRUNE_WRITE_UNRESTRICTED && scope != SUCRUNE_WRITE_READ_ONLY && scope != SUCRUNE_WRITE_PROJECT)
        return -EINVAL;
    if (profile != SUCRUNE_WORKSPACE_BUNDLED && profile != SUCRUNE_WORKSPACE_LINUX && profile != SUCRUNE_WORKSPACE_BUILD) return -EINVAL;
    if (mount && (profile==SUCRUNE_WORKSPACE_BUNDLED || !mount->stat || !mount->list || !mount->open ||
        !mount->mkdir || !mount->remove || !mount->rename || !mount->destroy)) return -EINVAL;
    if (network_policy!=SUCRUNE_NETWORK_NONE && network_policy!=SUCRUNE_NETWORK_LOOPBACK && network_policy!=SUCRUNE_NETWORK_OUTBOUND) return -EINVAL;
    if (network_handle!=0U && network_policy!=SUCRUNE_NETWORK_OUTBOUND) return -EINVAL;
    int root = open(workspace, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return -errno;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) { int e = errno; (void)close(root); return -e; }
    int done[2];
    if (pipe2(done, O_CLOEXEC) != 0) { int e = errno; (void)close(root); (void)close(pair[0]); (void)close(pair[1]); return -e; }
    struct broker *b = calloc(1U, sizeof(*b));
    if (b == NULL) { (void)close(root); (void)close(pair[0]); (void)close(pair[1]); (void)close(done[0]); (void)close(done[1]); return -ENOMEM; }
    b->root = root; b->socket = pair[0]; b->completion = done[1];
    b->creation_mask = 0077;
    b->profile = profile;
    b->write_scope = scope;
    b->trusted_exec = image;
    sucrune_exec_image_retain(image);
    b->resource_limit = profile == SUCRUNE_WORKSPACE_BUNDLED ? SUCRUNE_DEFAULT_FILE_RESOURCES : SUCRUNE_FILE_RESOURCES;
    b->links.parent=-1;b->links.store=-1;b->links.base=-1;
    b->network_handle=network_handle;
    for (int i = 0; i < FILE_SLOTS; i++) b->files[i] = -1;
    b->cwd = fcntl(root,F_DUPFD_CLOEXEC,3);
    int error = b->cwd < 0 ? -errno : setup_network(b,network_policy);
    if(error==0) error=sucrune_links_init(&b->links,root,workspace);
    b->family=calloc(1,sizeof(*b->family));
    if(b->family==NULL) error=-ENOMEM;
    else {
        atomic_init(&b->family->sessions,1U);
        b->family->mount_anchor=-1;
        if (mount) {
            b->family->mount=*mount;
            *consumed=true;
            b->family->mount_anchor=openat(root,"workspace",O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
            if (b->family->mount_anchor<0 && !error) error=-errno;
        }
    }
    if(error==0) error=start_server(b);
    if(error!=0) {destroy_server(b);(void)close(pair[1]);(void)close(done[0]);return error;}
    *completion = done[0];
    return pair[1];
}
int sucrune_workspace_broker_mounted(const char *workspace,int *completion,int policy,
                                   uint64_t handle,enum sucrune_workspace_profile profile,
                                   enum sucrune_write_scope scope,struct sucrune_exec_image *image,
                                   const struct sucrune_guest_directory *mount) {
    bool consumed=false;
    int rc=create_broker(workspace,completion,policy,handle,profile,scope,image,mount,&consumed);
    if (mount && !consumed && mount->destroy) mount->destroy(mount->context);
    return rc;
}
int sucrune_workspace_broker_with_image(const char *workspace, int *completion, int policy,
                                   uint64_t handle,enum sucrune_workspace_profile profile,
                                   enum sucrune_write_scope scope,struct sucrune_exec_image *image) {
    return sucrune_workspace_broker_mounted(workspace,completion,policy,handle,profile,scope,image,NULL);
}
int sucrune_workspace_broker_scoped(const char *workspace, int *completion, int network_policy,
                                    uint64_t network_handle, enum sucrune_workspace_profile profile,
                                    enum sucrune_write_scope scope) {
    return sucrune_workspace_broker_with_image(workspace, completion, network_policy, network_handle, profile, scope, NULL);
}
int sucrune_workspace_broker_profile(const char *workspace, int *completion, int policy,
                                     uint64_t network_handle, enum sucrune_workspace_profile profile) {
    return sucrune_workspace_broker_scoped(workspace, completion, policy, network_handle, profile, SUCRUNE_WRITE_UNRESTRICTED);
}
int sucrune_workspace_broker_with_network_handle(const char *workspace, int *completion, int policy, uint64_t network_handle) {
    return sucrune_workspace_broker_profile(workspace, completion, policy, network_handle, SUCRUNE_WORKSPACE_BUNDLED);
}
int sucrune_workspace_broker_with_network(const char *workspace, int *completion, int network_policy) {
    return sucrune_workspace_broker_with_network_handle(workspace,completion,network_policy,0U);
}
int sucrune_workspace_broker(const char *workspace, int *completion) {
    return sucrune_workspace_broker_with_network(workspace, completion, SUCRUNE_NETWORK_NONE);
}
