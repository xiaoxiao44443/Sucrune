/* Included after runtime_jni's standard UTF-8 string helpers. The callback object
 * lives only in the Android manager. Untrusted worker processes see broker handles. */
#include "guest_directory.h"
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

struct java_directory {
    JavaVM *vm;
    jobject object;
    jclass errno_type;
    jfieldID errno_field;
    jmethodID stat, list, open, mkdir, remove, rename, detach_fd;
};

struct directory_call {
    JNIEnv *env;
    bool attached;
};

static pthread_key_t directory_thread_key;
static pthread_once_t directory_key_once = PTHREAD_ONCE_INIT;
static int directory_key_result;
static void detach_directory_thread(void *pointer) {
    JavaVM *vm = pointer;
    (*vm)->DetachCurrentThread(vm);
}
static void make_directory_key(void) {
    directory_key_result = pthread_key_create(&directory_thread_key, detach_directory_thread);
}

static int directory_exception(JNIEnv *env, struct java_directory *dir) {
    jthrowable ex = (*env)->ExceptionOccurred(env);
    if (ex == NULL) return 0;
    (*env)->ExceptionClear(env);
    int error = EIO;
    if ((*env)->IsInstanceOf(env, ex, dir->errno_type)) {
        jint code = (*env)->GetIntField(env, ex, dir->errno_field);
        if (code > 0 && code < 4096) error = code;
    }
    (*env)->DeleteLocalRef(env, ex);
    return -error;
}

static int directory_enter(struct java_directory *dir, struct directory_call *call) {
    JavaVM *vm = dir->vm;
    jint status = (*vm)->GetEnv(vm, (void **)&call->env, JNI_VERSION_1_6);
    call->attached = status == JNI_EDETACHED;
    if (call->attached) {
        status = (*vm)->AttachCurrentThread(vm, &call->env, NULL);
        // A broker worker performs many lookups. Attach once for its lifetime.
        if (status == JNI_OK && pthread_once(&directory_key_once, make_directory_key) == 0 &&
                directory_key_result == 0 && pthread_setspecific(directory_thread_key, vm) == 0) {
            call->attached = false;
        }
    }
    if (status != JNI_OK) return -EIO;
    if ((*call->env)->PushLocalFrame(call->env, 16) == 0) return 0;
    (*call->env)->ExceptionClear(call->env);
    if (call->attached) (*vm)->DetachCurrentThread(vm);
    return -ENOMEM;
}

static void directory_leave(struct java_directory *dir, struct directory_call *call) {
    (*call->env)->PopLocalFrame(call->env, NULL);
    if (call->attached) (*dir->vm)->DetachCurrentThread(dir->vm);
}

static int directory_path(JNIEnv *env, const char *path, jstring *value) {
    *value = java_string(env, path);
    if (!*value) return -ENOMEM;
    /* Linux paths are byte strings and Java replaces malformed UTF-8. Never
     * allow two different names to silently resolve to the same host document. */
    char *encoded = utf8(env, *value);
    if (!encoded) return -ENOMEM;
    int result = strcmp(encoded, path) == 0 ? 0 : -EILSEQ;
    free(encoded);
    return result;
}

static int directory_stat(void *context, const char *path, struct stat *out) {
    struct java_directory *dir = context;
    struct directory_call call;
    int result = directory_enter(dir, &call);
    if (result < 0) return result;
    JNIEnv *env = call.env;
    jstring name;
    result = directory_path(env, path, &name);
    if (result == 0) {
        jlongArray response = (*env)->CallObjectMethod(env, dir->object, dir->stat, name);
        result = directory_exception(env, dir);
        jsize n = !result && response ? (*env)->GetArrayLength(env, response) : 0;
        if (!result && n != 3 && n != 5) result = -EIO;
        if (!result) {
            jlong values[5] = {0};
            (*env)->GetLongArrayRegion(env, response, 0, n, values);
            result = directory_exception(env, dir);
            if (!result && values[1] < 0) result = -EIO;
            if (!result) {
                memset(out, 0, sizeof(*out));
                out->st_mode = (mode_t)values[0];
                if (!S_ISDIR(out->st_mode) && !S_ISREG(out->st_mode)) result = -EOPNOTSUPP;
                out->st_nlink = S_ISDIR(out->st_mode) ? 2 : 1;
                out->st_size = (off_t)values[1];
                out->st_dev = (dev_t)values[3];
                out->st_ino = (ino_t)values[4];
                int64_t millis = values[2];
                out->st_mtim.tv_sec = (time_t)(millis / 1000);
                out->st_mtim.tv_nsec = (long)(millis % 1000) * 1000000L;
                if (out->st_mtim.tv_nsec < 0) { out->st_mtim.tv_sec--; out->st_mtim.tv_nsec += 1000000000L; }
                out->st_atim = out->st_ctim = out->st_mtim;
                out->st_blksize = 4096;
            }
        }
    }
    if ((*env)->ExceptionCheck(env)) result = directory_exception(env, dir);
    directory_leave(dir, &call);
    return result;
}

JNIEXPORT jint JNICALL Java_com_sucrune_probe_NativeProbe_unlinkDirectoryEntry(JNIEnv *env, jclass klass,
        jint directory_fd, jstring child, jboolean directory) {
    (void)klass;
    char *name = utf8(env, child);
    if (!name) return -EINVAL;
    int result = -EINVAL;
    struct stat parent;
    if (*name && strlen(name) <= NAME_MAX && !strchr(name, '/') && strcmp(name, ".") && strcmp(name, "..")) {
        if (fstat(directory_fd, &parent) < 0) result = -errno;
        else if (!S_ISDIR(parent.st_mode)) result = -ENOTDIR;
        else result = unlinkat(directory_fd, name, directory ? AT_REMOVEDIR : 0) == 0 ? 0 : -errno;
    }
    free(name);
    return result;
}

static int directory_list(void *context, const char *path, char ***names, size_t *count) {
    struct java_directory *dir = context;
    struct directory_call call;
    int result = directory_enter(dir, &call);
    if (result < 0) return result;
    JNIEnv *env = call.env;
    jstring name;
    result = directory_path(env, path, &name);
    jobjectArray arr = NULL;
    if (result == 0) {
        arr = (*env)->CallObjectMethod(env, dir->object, dir->list, name);
        result = directory_exception(env, dir);
        if (!result && !arr) result = -EIO;
    }
    size_t n = !result ? (size_t)(*env)->GetArrayLength(env, arr) : 0;
    char **entries = n ? calloc(n, sizeof(*entries)) : NULL;
    if (n && !entries) result = -ENOMEM;
    for (size_t i = 0; !result && i < n; i++) {
        jstring entry = (*env)->GetObjectArrayElement(env, arr, (jsize)i);
        entries[i] = entry ? utf8(env, entry) : NULL;
        if (entry) (*env)->DeleteLocalRef(env, entry);
        if (!entries[i] || !*entries[i] || strlen(entries[i]) > NAME_MAX || strchr(entries[i], '/') ||
                strcmp(entries[i], ".") == 0 || strcmp(entries[i], "..") == 0) result = -EIO;
    }
    if ((*env)->ExceptionCheck(env)) result = directory_exception(env, dir);
    if (result) {
        if (entries) for (size_t i = 0; i < n; i++) free(entries[i]);
        free(entries);
    } else { *names = entries; *count = n; }
    directory_leave(dir, &call);
    return result;
}

static int directory_open(void *context, const char *path, int flags, mode_t mode) {
    struct java_directory *dir = context;
    struct directory_call call;
    int result = directory_enter(dir, &call);
    if (result < 0) return result;
    JNIEnv *env = call.env;
    jstring name;
    result = directory_path(env, path, &name);
    if (!result) {
        jobject pfd = (*env)->CallObjectMethod(env, dir->object, dir->open, name, (jint)flags, (jint)mode);
        result = directory_exception(env, dir);
        if (!result) result = pfd ? (*env)->CallIntMethod(env, pfd, dir->detach_fd) : -EIO;
    }
    if ((*env)->ExceptionCheck(env)) result = directory_exception(env, dir);
    directory_leave(dir, &call);
    return result;
}

static int directory_mutate(struct java_directory *dir, jmethodID method, const char *path,
                            const char *target, int flags) {
    struct directory_call call;
    int result = directory_enter(dir, &call);
    if (result < 0) return result;
    JNIEnv *env = call.env;
    jstring name, destination;
    result = directory_path(env, path, &name);
    if (!result && target) result = directory_path(env, target, &destination);
    if (!result) {
        if (target) (*env)->CallVoidMethod(env, dir->object, method, name, destination, (jint)flags);
        else if (method == dir->remove) (*env)->CallVoidMethod(env, dir->object, method, name, (jboolean)flags);
        else (*env)->CallVoidMethod(env, dir->object, method, name);
    }
    if ((*env)->ExceptionCheck(env)) result = directory_exception(env, dir);
    directory_leave(dir, &call);
    return result;
}
static int directory_mkdir(void *ctx, const char *path) {
    struct java_directory *dir = ctx;
    return directory_mutate(dir, dir->mkdir, path, NULL, 0);
}
static int directory_remove(void *ctx, const char *path, bool isdir) {
    struct java_directory *dir = ctx;
    return directory_mutate(dir, dir->remove, path, NULL, isdir);
}
static int directory_rename(void *ctx, const char *path, const char *to, unsigned int flags) {
    struct java_directory *dir = ctx;
    return directory_mutate(dir, dir->rename, path, to, (int)flags);
}

static void directory_release(void *ctx) {
    struct java_directory *dir = ctx;
    struct directory_call call;
    if (directory_enter(dir, &call) == 0) {
        (*call.env)->DeleteGlobalRef(call.env, dir->object);
        (*call.env)->DeleteGlobalRef(call.env, dir->errno_type);
        directory_leave(dir, &call);
    }
    free(dir);
}

static int directory_callbacks(JNIEnv *env, jobject object, struct sucrune_guest_directory *out) {
    struct java_directory *dir = calloc(1, sizeof(*dir));
    if (!dir) return -ENOMEM;
    jclass klass = (*env)->GetObjectClass(env, object);
    jclass err = (*env)->FindClass(env, "android/system/ErrnoException");
    jclass pfd = (*env)->FindClass(env, "android/os/ParcelFileDescriptor");
    if (!klass || !err || !pfd || (*env)->GetJavaVM(env, &dir->vm) != JNI_OK) goto error;
    dir->object = (*env)->NewGlobalRef(env, object);
    dir->errno_type = (jclass)(*env)->NewGlobalRef(env, err);
    if (!dir->errno_type || !dir->object) goto error;
    dir->errno_field = (*env)->GetFieldID(env, err, "errno", "I");
    dir->detach_fd = (*env)->GetMethodID(env, pfd, "detachFd", "()I");
    dir->stat = (*env)->GetMethodID(env, klass, "stat", "(Ljava/lang/String;)[J");
    dir->list = (*env)->GetMethodID(env, klass, "list", "(Ljava/lang/String;)[Ljava/lang/String;");
    dir->open = (*env)->GetMethodID(env, klass, "open", "(Ljava/lang/String;II)Landroid/os/ParcelFileDescriptor;");
    dir->mkdir = (*env)->GetMethodID(env, klass, "mkdir", "(Ljava/lang/String;)V");
    dir->remove = (*env)->GetMethodID(env, klass, "remove", "(Ljava/lang/String;Z)V");
    dir->rename = (*env)->GetMethodID(env, klass, "rename", "(Ljava/lang/String;Ljava/lang/String;I)V");
    if (!dir->stat || !dir->list || !dir->open || !dir->mkdir || !dir->remove || !dir->rename ||
            !dir->errno_field || !dir->detach_fd) goto error;
    *out = (struct sucrune_guest_directory){ .context=dir, .destroy=directory_release, .stat=directory_stat,
        .list=directory_list, .open=directory_open, .mkdir=directory_mkdir, .remove=directory_remove, .rename=directory_rename };
    return 0;
error:
    (*env)->ExceptionClear(env);
    if (dir->object) (*env)->DeleteGlobalRef(env, dir->object);
    if (dir->errno_type) (*env)->DeleteGlobalRef(env, dir->errno_type);
    free(dir);
    return -EIO;
}
