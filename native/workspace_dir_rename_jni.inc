/* A host may hold SAF-opened parent directory descriptors even when raw storage access is
 * restricted. Let the kernel enforce scoped-storage admission and atomic rename semantics.
 * Never replace a failed operation with copy+unlink. */
#include <sys/syscall.h>
#include <stdio.h>

JNIEXPORT jint JNICALL Java_com_sucrune_probe_NativeProbe_directoryOpenFlag(JNIEnv *env, jclass klass) {
    (void)env; (void)klass;
    return O_DIRECTORY;
}

JNIEXPORT jint JNICALL Java_com_sucrune_probe_NativeProbe_checkDocumentOpenMode(
        JNIEnv *env, jclass klass, jint fd, jint access, jboolean append) {
    (void)env; (void)klass;
    const int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -errno;
    if (access != O_RDONLY && access != O_WRONLY && access != O_RDWR) return -EINVAL;
    if ((flags & O_ACCMODE) != access) return -EOPNOTSUPP;
    const int desired = append ? flags | O_APPEND : flags & ~O_APPEND;
    return desired == flags || fcntl(fd, F_SETFL, desired) == 0 ? 0 : -errno;
}

static int rename_parent(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) return -errno;
    return S_ISDIR(st.st_mode) ? 0 : -ENOTDIR;
}

static bool rename_component(const char *name) {
    return name && name[0] && strlen(name) <= NAME_MAX && !strchr(name, '/') &&
           !strchr(name, '\\') && strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

JNIEXPORT jint JNICALL Java_com_sucrune_probe_NativeProbe_renameDirectoryEntry(
        JNIEnv *env, jclass klass, jint oldfd, jstring old_child, jint newfd, jstring new_child, jint flags) {
    (void)klass;
    if (flags != 0 && flags != 1) return -EOPNOTSUPP;
    int error = rename_parent(oldfd);
    if (error == 0) error = rename_parent(newfd);
    if (error != 0) return error;
    char *before = utf8(env, old_child);
    char *after = before ? utf8(env, new_child) : NULL;
    if (!rename_component(before) || !rename_component(after)) error = -EINVAL;
    else if (flags == 0) error = renameat(oldfd, before, newfd, after) == 0 ? 0 : -errno;
    else error = syscall(__NR_renameat2, oldfd, before, newfd, after, 1U) == 0 ? 0 : -errno;
    free(before);
    free(after);
    return error;
}
