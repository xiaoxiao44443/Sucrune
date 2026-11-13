#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "workspace_broker.h"
#include "trusted_exec_image.h"
#include "process_probe.h"
#include "shell_runtime.h"
#include "linux_runner.h"
#include "program_catalog.h"

/* JNI modified UTF-8 is not ordinary UTF-8 (notably for emoji). Convert via
 * byte arrays at this boundary so scripts, filenames and JSON round-trip. */
static char *utf8(JNIEnv *env, jstring value) {
    if (value == NULL) return NULL;
    jclass type = (*env)->FindClass(env, "java/lang/String");
    if (type == NULL) return NULL;
    jmethodID get = (*env)->GetMethodID(env, type, "getBytes", "(Ljava/lang/String;)[B");
    if (get == NULL) { (*env)->DeleteLocalRef(env, type); return NULL; }
    jstring charset = (*env)->NewStringUTF(env, "UTF-8");
    if (charset == NULL) { (*env)->DeleteLocalRef(env, type); return NULL; }
    jbyteArray bytes = (jbyteArray)(*env)->CallObjectMethod(env, value, get, charset);
    (*env)->DeleteLocalRef(env, charset); (*env)->DeleteLocalRef(env, type);
    if ((*env)->ExceptionCheck(env) || bytes == NULL) return NULL;
    jsize length = (*env)->GetArrayLength(env, bytes);
    if (length > 2 * 1024 * 1024) { (*env)->DeleteLocalRef(env, bytes); return NULL; }
    char *result = malloc((size_t)length + 1U);
    if (result != NULL) {
        (*env)->GetByteArrayRegion(env, bytes, 0, length, (jbyte *)result);
        if ((*env)->ExceptionCheck(env)) { free(result); (*env)->DeleteLocalRef(env, bytes); return NULL; }
        result[length] = '\0';
        if (memchr(result, 0, (size_t)length) != NULL) { free(result); result = NULL; }
    }
    (*env)->DeleteLocalRef(env, bytes);
    return result;
}
static jstring java_string(JNIEnv *env, const char *text) {
    size_t length = strlen(text);
    if (length > INT32_MAX) return NULL;
    jbyteArray bytes = (*env)->NewByteArray(env, (jsize)length);
    if (bytes == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, bytes, 0, (jsize)length, (const jbyte *)text);
    if ((*env)->ExceptionCheck(env)) { (*env)->DeleteLocalRef(env, bytes); return NULL; }
    jclass type = (*env)->FindClass(env, "java/lang/String");
    if (type == NULL) { (*env)->DeleteLocalRef(env, bytes); return NULL; }
    jmethodID constructor = (*env)->GetMethodID(env, type, "<init>", "([BLjava/lang/String;)V");
    if (constructor == NULL) { (*env)->DeleteLocalRef(env, type); (*env)->DeleteLocalRef(env, bytes); return NULL; }
    jstring charset = (*env)->NewStringUTF(env, "UTF-8");
    if (charset == NULL) { (*env)->DeleteLocalRef(env, type); (*env)->DeleteLocalRef(env, bytes); return NULL; }
    jstring result = (jstring)(*env)->NewObject(env, type, constructor, bytes, charset);
    (*env)->DeleteLocalRef(env, charset); (*env)->DeleteLocalRef(env, type); (*env)->DeleteLocalRef(env, bytes);
    return result;
}
typedef char *(*core_call_type)(char *, char *);
typedef void (*core_free_type)(char *);
static core_call_type core_call;
static core_free_type core_free;
static pthread_once_t core_once = PTHREAD_ONCE_INIT;
static void load_core(void) {
    // Called only by the manager's coreCall. The isolated guest workers never
    // dlopen Go, so its runtime signal handlers cannot own their SIGSYS path.
    void *library = dlopen("libsucrune_core.so", RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) return;
    core_call = (core_call_type)dlsym(library, "SucruneCoreCall");
    core_free = (core_free_type)dlsym(library, "SucruneCoreFree");
}
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_NativeProbe_coreCall(JNIEnv *env, jclass type, jstring directory, jstring request) {
    (void)type;
    char *path = utf8(env, directory);
    if ((*env)->ExceptionCheck(env)) { free(path); return NULL; }
    char *json = utf8(env, request);
    if ((*env)->ExceptionCheck(env)) { free(path); free(json); return NULL; }
    if (path == NULL || json == NULL) {
        free(path); free(json);
        return java_string(env, "{\"ok\":false,\"error\":{\"code\":\"invalid_arguments\",\"message\":\"Invalid UTF-8 input or request size.\"}}");
    }
    (void)pthread_once(&core_once, load_core);
    if (core_call == NULL || core_free == NULL) {
        free(path); free(json);
        return java_string(env, "{\"ok\":false,\"error\":{\"code\":\"core_unavailable\",\"message\":\"Cannot load the packaged Go management core.\"}}");
    }
    char *result = core_call(path, json);
    free(path); free(json);
    if (result == NULL) return java_string(env, "{\"ok\":false,\"error\":{\"code\":\"core_failure\",\"message\":\"No core response.\"}}");
    jstring value = java_string(env, result);
    core_free(result);
    return value;
}
static jintArray workspace_descriptors(JNIEnv *env, int result, int completion) {
    jint descriptors[2] = {result, completion};
    jsize count = result < 0 ? 1 : 2;
    jintArray value = (*env)->NewIntArray(env, count);
    if (value != NULL) (*env)->SetIntArrayRegion(env, value, 0, count, descriptors);
    else if (result >= 0) { (void)close(result); (void)close(completion); }
    return value;
}
static jintArray open_workspace(JNIEnv *env, jstring directory, int policy, uint64_t network_handle,
        enum sucrune_workspace_profile profile, enum sucrune_write_scope scope, struct sucrune_exec_image *image) {
    char *path = utf8(env, directory);
    if ((*env)->ExceptionCheck(env)) { free(path); return NULL; }
    int completion = -1;
    int result = path == NULL ? -EINVAL : sucrune_workspace_broker_with_image(path, &completion, policy,
            network_handle, profile, scope, image);
    free(path);
    return workspace_descriptors(env, result, completion);
}
#include "guest_directory_jni.inc"
#include "workspace_dir_rename_jni.inc"

static jintArray configured_workspace(JNIEnv *env, jstring directory, jint policy, jlong network_handle,
        jboolean build, jint scope, jstring guest_path, jbyteArray data, jobject mount,
        const char *source_workspace, const char *source_subdir, const char *guest_target) {
    struct sucrune_exec_image *image = NULL;
    if ((data == NULL) != (guest_path == NULL)) return workspace_descriptors(env, -EINVAL, -1);
    if (data) {
        jsize length = (*env)->GetArrayLength(env, data);
        if (!length || (size_t)length > SUCRUNE_TRUSTED_IMAGE_LIMIT) return workspace_descriptors(env, -EINVAL, -1);
        char *name = utf8(env, guest_path);
        if (!name || (*env)->ExceptionCheck(env)) { free(name); return NULL; }
        jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
        if (!bytes) { free(name); return NULL; }
        int rc = sucrune_exec_image_create(name, bytes, (size_t)length, &image);
        (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
        free(name);
        if (rc < 0) return workspace_descriptors(env, rc, -1);
    }
    int completion = -1;
    int result = -EINVAL;
    char *path = utf8(env, directory);
    enum sucrune_workspace_profile profile = build ? SUCRUNE_WORKSPACE_BUILD : SUCRUNE_WORKSPACE_LINUX;
    if (path) {
        struct sucrune_guest_directory callbacks;
        result = mount ? directory_callbacks(env, mount, &callbacks) : 0;
        if (!result) {
            const struct sucrune_guest_directory *directory_mount = mount ? &callbacks : NULL;
            if (source_workspace) {
                result = sucrune_workspace_broker_bind(path, &completion, policy, (uint64_t)network_handle,
                    profile, (enum sucrune_write_scope)scope, image, directory_mount,
                    source_workspace, source_subdir, guest_target);
            } else {
                result = sucrune_workspace_broker_mounted(path, &completion, policy, (uint64_t)network_handle,
                    profile, (enum sucrune_write_scope)scope, image, directory_mount);
            }
        }
    }
    free(path);
    if (image) sucrune_exec_image_release(image);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return workspace_descriptors(env, result, completion);
}

JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openWorkspaceWithImage(JNIEnv *env, jclass type,
        jstring directory, jint policy, jlong network_handle, jboolean build, jint scope, jstring guest_path, jbyteArray data) {
    (void)type;
    if (!data) return workspace_descriptors(env, -EINVAL, -1);
    return configured_workspace(env, directory, policy, network_handle, build, scope, guest_path, data, NULL,
        NULL, NULL, NULL);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openWorkspaceWithDirectory(JNIEnv *env, jclass type,
        jstring directory, jint policy, jlong network_handle, jboolean build, jint scope,
        jstring guest_path, jbyteArray data, jobject mount) {
    (void)type;
    if (!mount) return workspace_descriptors(env, -EINVAL, -1);
    return configured_workspace(env, directory, policy, network_handle, build, scope, guest_path, data, mount,
        NULL, NULL, NULL);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openWorkspaceWithBind(JNIEnv *env, jclass type,
        jstring directory, jint policy, jlong network_handle, jboolean build, jint scope, jstring guest_path,
        jbyteArray data, jobject mount, jstring source_workspace, jstring source_subdir, jstring guest_target) {
    (void)type;
    char *source = utf8(env, source_workspace);
    char *subdir = source ? utf8(env, source_subdir) : NULL;
    char *target = subdir ? utf8(env, guest_target) : NULL;
    jintArray value = NULL;
    if (!(*env)->ExceptionCheck(env)) {
        value = target ? configured_workspace(env, directory, policy, network_handle, build, scope, guest_path,
            data, mount, source, subdir, target) : workspace_descriptors(env, -EINVAL, -1);
    }
    free(source);
    free(subdir);
    free(target);
    return value;
}
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_NativeProbe_runProcessProbe(JNIEnv *env, jclass type, jstring runner_path) {
    (void)type;
    char *path = utf8(env, runner_path);
    if ((*env)->ExceptionCheck(env)) { free(path); return NULL; }
    char report[16384];
    int result = sucrune_process_probe_spawn(path, report, sizeof(report));
    free(path);
    if (result < 0) (void)snprintf(report, sizeof(report),
        "{\"schema_version\":1,\"stage\":\"process_probe_wrapper\",\"error_number\":%d}", -result);
    return java_string(env, report);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openWorkspace(JNIEnv *env, jclass type, jstring directory) {
    (void)type; return open_workspace(env, directory, 0, 0U, SUCRUNE_WORKSPACE_BUNDLED, SUCRUNE_WRITE_UNRESTRICTED, NULL);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openWorkspaceWithNetwork(JNIEnv *env, jclass type,
        jstring directory, jint policy) {
    (void)type; return open_workspace(env, directory, policy, 0U, SUCRUNE_WORKSPACE_BUNDLED, SUCRUNE_WRITE_UNRESTRICTED, NULL);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openBuildWorkspace(JNIEnv *env, jclass type,
        jstring directory, jint policy, jlong network_handle) {
    (void)type; return open_workspace(env, directory, policy, (uint64_t)network_handle, SUCRUNE_WORKSPACE_BUILD, SUCRUNE_WRITE_UNRESTRICTED, NULL);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openWorkspaceOnNetwork(JNIEnv *env, jclass type,
        jstring directory, jint policy, jlong network_handle) {
    (void)type; return open_workspace(env, directory, policy, (uint64_t)network_handle, SUCRUNE_WORKSPACE_LINUX, SUCRUNE_WRITE_UNRESTRICTED, NULL);
}
JNIEXPORT jintArray JNICALL Java_com_sucrune_probe_NativeProbe_openScopedWorkspace(JNIEnv *env, jclass type,
        jstring directory, jint network_policy, jlong network_handle, jboolean build, jint scope) {
    (void)type;
    return open_workspace(env, directory, network_policy, (uint64_t)network_handle,
            build ? SUCRUNE_WORKSPACE_BUILD : SUCRUNE_WORKSPACE_LINUX, (enum sucrune_write_scope)scope, NULL);
}
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_NativeProbe_runShell(JNIEnv *env, jclass type,
        jint broker, jstring script, jstring directory, jint output, jint error_output) {
    (void)type;
    char *source = utf8(env, script);
    if ((*env)->ExceptionCheck(env)) { free(source); return NULL; }
    char *cwd = utf8(env, directory);
    if ((*env)->ExceptionCheck(env)) { free(source); free(cwd); return NULL; }
    char report[4096];
    (void)sucrune_shell_run(broker, source, cwd, output, error_output, report, sizeof(report));
    free(source); free(cwd);
    return java_string(env, report);
}

static int utf8_array(JNIEnv *env, jobjectArray values, char **strings, size_t *count) {
    if (values == NULL) return -1;
    jsize length = (*env)->GetArrayLength(env, values);
    if (length < 0 || length > 64) return -1;
    size_t bytes = 0;
    for (jsize i = 0; i < length; i++) {
        jstring value = (jstring)(*env)->GetObjectArrayElement(env, values, i);
        if ((*env)->ExceptionCheck(env)) return -1;
        char *converted = utf8(env, value);
        if (value != NULL) (*env)->DeleteLocalRef(env, value);
        if ((*env)->ExceptionCheck(env) || converted == NULL) { free(converted); return -1; }
        strings[*count] = converted; (*count)++;
        size_t size = strlen(converted);
        if (size > 4096U || bytes + size + 1U > 65536U) return -1;
        bytes += size + 1U;
    }
    return 0;
}
JNIEXPORT jstring JNICALL Java_com_sucrune_probe_NativeProbe_runProgram(JNIEnv *env, jclass type,
        jint broker, jstring program, jobjectArray arguments, jobjectArray environment,
        jstring directory, jint output, jint error_output, jint input) {
    (void)type;
    char *name = utf8(env, program), *cwd = NULL;
    char *argv[64] = {0}, *envp[64] = {0};
    size_t argc = 0, envc = 0;
    char report[4096] = "{\"schema_version\":1,\"kind\":\"program\",\"status\":\"failed\",\"stage\":\"arguments\",\"message\":\"Invalid UTF-8 program arguments.\"}";
    if (!(*env)->ExceptionCheck(env) && name != NULL) cwd = utf8(env, directory);
    if (!(*env)->ExceptionCheck(env) && name != NULL && cwd != NULL &&
        utf8_array(env, arguments, argv, &argc) == 0 && utf8_array(env, environment, envp, &envc) == 0) {
        (void)sucrune_program_run(broker, name, argc, (const char *const *)argv,
            envc, (const char *const *)envp, cwd, output, error_output, report, sizeof(report), input);
    } else if (input >= 0) (void)close(input);
    free(name); free(cwd);
    for (size_t i = 0; i < argc; i++) free(argv[i]);
    for (size_t i = 0; i < envc; i++) free(envp[i]);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return java_string(env, report);
}

JNIEXPORT jstring JNICALL Java_com_sucrune_probe_NativeProbe_listPrograms(JNIEnv *env, jclass type) {
    (void)type;
    char catalog[2048];
    if (sucrune_program_list(catalog, sizeof(catalog)) != 0) return java_string(env, "[]");
    return java_string(env, catalog);
}

JNIEXPORT jstring JNICALL Java_com_sucrune_probe_NativeProbe_runLinux(JNIEnv *env, jclass type,
        jint broker, jstring path, jobjectArray arguments, jobjectArray environment,
        jstring directory, jint output, jint error_output, jint input, jint stop) {
    (void)type;
    char *name = utf8(env, path), *cwd = NULL;
    char *argv[64] = {0}, *envp[64] = {0};
    size_t argc = 0, envc = 0;
    char report[4096] = "{\"schema_version\":1,\"kind\":\"linux\",\"status\":\"failed\",\"stage\":\"arguments\",\"message\":\"Invalid UTF-8 Linux arguments.\"}";
    if (!(*env)->ExceptionCheck(env) && name != NULL) cwd = utf8(env, directory);
    if (!(*env)->ExceptionCheck(env) && name != NULL && cwd != NULL &&
        utf8_array(env, arguments, argv, &argc) == 0 && utf8_array(env, environment, envp, &envc) == 0) {
        (void)sucrune_linux_spawn(broker, name, argc, (const char *const *)argv,
            envc, (const char *const *)envp, cwd, output, error_output, report, sizeof(report), input, stop);
    } else if (input >= 0) (void)close(input);
    free(name); free(cwd);
    for (size_t i = 0; i < argc; i++) free(argv[i]);
    for (size_t i = 0; i < envc; i++) free(envp[i]);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return java_string(env, report);
}
