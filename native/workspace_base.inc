/* APK-owned immutable content. A reference is a project-local symlink with
 * an opaque target. Never follow it through the host pathname resolver. */
static int base_key(int parent, const char *name, char key[70], mode_t *mode) {
    const size_t prefix = sizeof(SUCRUNE_BASE_MARKER_PREFIX) - 1;
    char target[sizeof(SUCRUNE_BASE_MARKER_PREFIX) + 69];
    ssize_t n = readlinkat(parent, name, target, sizeof(target));
    if (n < 0) return errno == EINVAL || errno == ENOENT ? 0 : -errno;
    if ((size_t)n < prefix || memcmp(target, SUCRUNE_BASE_MARKER_PREFIX, prefix)) return 0;
    if ((size_t)n != prefix + 69) return -EUCLEAN;
    memcpy(key, target + prefix, 69);
    key[69] = 0;
    if (key[0] != '0' || key[4] != '-' || strspn(key + 1, "01234567") != 3 ||
        strspn(key + 5, "0123456789abcdef") != 64) return -EUCLEAN;
    *mode = (mode_t)(((key[1]-'0') << 6) | ((key[2]-'0') << 3) | (key[3]-'0'));
    return 1;
}

static int base_directory(struct sucrune_workspace_links *l) {
    /* Only the manager's environments/<id>/workspace layout opts in. */
    if (strcmp(l->name, "workspace.sucrune-inodes-v1")) return -EACCES;
    const int flags = O_NOFOLLOW | O_CLOEXEC | O_DIRECTORY | O_RDONLY;
    int envs = openat(l->parent, "..", flags);
    if (envs < 0) return -errno;
    int manager = openat(envs, "..", flags);
    if (manager < 0) { int rc = -errno; close(envs); return rc; }
    struct stat actual, expected;
    int rc = 0;
    if (fstat(envs, &actual) || fstatat(manager, "environments", &expected, AT_SYMLINK_NOFOLLOW)) rc = -errno;
    else if (actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) rc = -EACCES;
    close(envs);
    if (!rc) {
        int directory = openat(manager, "shared-tools-v1", flags);
        if (directory < 0) rc = -errno;
        else if (fstat(directory, &actual) || actual.st_uid != geteuid() || (actual.st_mode & 07777) != 0700) {
            close(directory);
            rc = -EACCES;
        } else l->base = directory;
    }
    close(manager);
    return rc;
}

static int base_body(struct sucrune_workspace_links *l, const char *key, mode_t mode, int flags) {
    /* musl includes O_PATH in O_ACCMODE. Both O_PATH and O_RDONLY are safe. */
    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) return -EINVAL;
    if (l->base < 0) {
        int rc = base_directory(l);
        if (rc < 0) return rc;
    }
    int body = openat(l->base, key, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOATIME);
    if (body < 0) return -errno;
    struct stat st;
    if (fstat(body, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        st.st_nlink != 1 || (st.st_mode & 07777) != mode) {
        close(body);
        return -EUCLEAN;
    }
    return body;
}

static int copy_body(int src, int dest) {
    char buf[65536];
    for (;;) {
        ssize_t n = read(src, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return n ? -errno : 0;
        for (ssize_t offset = 0; offset < n;) {
            ssize_t written = write(dest, buf + offset, (size_t)(n - offset));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return written < 0 ? -errno : -EIO;
            offset += written;
        }
    }
}

/* Caller holds the exclusive environment lock. The temporary file is outside
 * the guest root, on the same volume. A crash leaves the marker or a complete
 * private copy; the next promotion reclaims any partial staging file. */
int sucrune_base_promote(struct sucrune_workspace_links *l, int parent, const char *name) {
    char key[70];
    mode_t mode;
    int rc = base_key(parent, name, key, &mode);
    if (rc <= 0) return rc;
    int src = base_body(l, key, mode, O_RDONLY);
    if (src < 0) return src;
    const char *tmp = ".sucrune-copyup-v1";
    if (unlinkat(l->parent, tmp, 0) && errno != ENOENT) { rc = -errno; close(src); return rc; }
    int dst = openat(l->parent, tmp, O_NOFOLLOW | O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (dst < 0) { rc = -errno; close(src); return rc; }
    struct stat st;
    rc = fstat(src, &st) ? -errno : copy_body(src, dst);
    if (!rc && fchmod(dst, mode)) rc = -errno;
    if (!rc) {
        struct timespec times[] = {st.st_atim, st.st_mtim};
        if (futimens(dst, times) || fsync(dst)) rc = -errno;
    }
    if (close(dst) && !rc) rc = -errno;
    close(src);
    if (!rc && renameat(l->parent, tmp, parent, name)) rc = -errno;
    if (rc) (void)unlinkat(l->parent, tmp, 0);
    return rc ? rc : 1;
}
