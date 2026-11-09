#include <jni.h>
#include <stdio.h>

#include "probe.h"
#include "elf_probe.h"
#include "network_probe.h"

JNIEXPORT jstring JNICALL
Java_com_sucrune_probe_NativeProbe_runProbe(JNIEnv *env, jclass type) {
    (void)type;
    char report[SUCRUNE_PROBE_REPORT_CAPACITY];
    (void)sucrune_probe_run(report, sizeof(report));
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_sucrune_probe_NativeProbe_runElfProbe(JNIEnv *env, jclass type) {
    (void)type;
    char report[SUCRUNE_PROBE_REPORT_CAPACITY];
    (void)sucrune_elf_probe_run(report, sizeof(report));
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_com_sucrune_probe_NativeProbe_runNetworkProbe(JNIEnv *env, jclass type,
        jint mode, jint borrowed_fd, jint port, jint timeout_ms) {
    (void)type;
    char report[8192];
    int error = sucrune_network_probe_run(mode, borrowed_fd, port, timeout_ms,
        report, sizeof(report));
    if (error != 0) {
        (void)snprintf(report, sizeof(report),
            "{\"schema_version\":1,\"kind\":\"network_capability\",\"entry_error\":%d}", error);
    }
    return (*env)->NewStringUTF(env, report);
}
